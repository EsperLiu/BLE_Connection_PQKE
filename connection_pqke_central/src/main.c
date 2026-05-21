/*
 * connection-PQKE central / gateway
 *
 * Behaviour:
 *  1. Active scan for PQKE service UUID.
 *  2. Connect to matching peripheral.
 *  3. Exchange MTU.
 *  4. Discover CP, PK indication, PK CCC, CT write, and PQLVL.
 *  5. Read PQLVL.
 *  6. Subscribe to PK indication.
 *  7. Write CP_INIT = 0x02.
 *  8. Receive full PK by indication.
 *  9. Signal a dedicated worker thread.
 * 10. Worker runs ML-KEM encapsulation.
 * 11. Worker writes CT frames to peripheral.
 * 12. Worker polls CP until CP_DECAP_DONE.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/types.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>

#include <errno.h>
#include <string.h>

/* ML-KEM includes. Adjust folder paths if needed. */
#include "mlkem512/api.h"

#define CP_IDLE          0x00
#define CP_PING          0x01
#define CP_INIT          0x02
#define CP_KEY_READY     0x03
#define CP_CT_RECEIVED   0x04
#define CP_DECAP_DONE    0x05
#define CP_SESSION_DONE  0x06
#define CP_ERROR         0xff

#define MLKEM512_PK_BYTES   800U
#define MLKEM512_CT_BYTES   768U

#define MLKEM768_PK_BYTES   1184U
#define MLKEM768_CT_BYTES   1088U

#define MLKEM1024_PK_BYTES  1568U
#define MLKEM1024_CT_BYTES  1568U

#define PK_BUF_MAX          MLKEM1024_PK_BYTES
#define CT_BUF_MAX          MLKEM1024_CT_BYTES
#define SS_BYTES            32U

#define PQKE_WORKER_STACK_SIZE 40000
#define PQKE_WORKER_PRIORITY   7

/*
 * If your peripheral still expects the old CT frame format:
 *
 *   frame[0]     = frame number
 *   frame[1..N]  = ciphertext payload
 *
 * then CT_FRAME_LEN should match the peripheral-side CT_FRAME_LEN.
 *
 * The original design used:
 *   ML-KEM-512  : CTBYTES=768,  CT_FRAMES=2, CT_FRAME_LEN=385
 *   ML-KEM-768  : CTBYTES=1088, CT_FRAMES=3, CT_FRAME_LEN=364
 *   ML-KEM-1024 : CTBYTES=1568, CT_FRAMES=4, CT_FRAME_LEN=393
 */
#define CT_FRAME_LEN_512   385U
#define CT_FRAME_LEN_768   364U
#define CT_FRAME_LEN_1024  393U

static struct bt_conn *default_conn;

static uint16_t svc_start_handle;
static uint16_t svc_end_handle;
static uint16_t cp_value_handle;
static uint16_t pk_value_handle;
static uint16_t pk_ccc_handle;
static uint16_t ct_value_handle;
static uint16_t pqlvl_value_handle;

static uint8_t pk_buf[PK_BUF_MAX];
static uint8_t ct_buf[CT_BUF_MAX];
static uint8_t ss_buf[SS_BYTES];

static size_t pk_len;
static size_t expected_pk_len;
static size_t expected_ct_len;
static size_t ct_frame_len;

static uint8_t pqlvl;
static bool pk_complete;
static bool pqke_worker_busy;

static bool scan_match_seen;
static bool connecting;

K_SEM_DEFINE(pk_ready_sem, 0, 1);

static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_read_params read_params;
static struct bt_gatt_write_params write_params;
static struct bt_gatt_subscribe_params pk_subscribe_params;
static struct bt_gatt_exchange_params mtu_exchange_params;

static struct bt_uuid_128 pqke_svc_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcdef0));
static struct bt_uuid_128 cp_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde01));
static struct bt_uuid_128 pk_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde02));
static struct bt_uuid_128 ct_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde03));
static struct bt_uuid_128 pqlvl_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde04));

static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(BT_UUID_GATT_CCC_VAL);

/*
 * Hard-coded advertising byte order for:
 * 12345678-1234-5678-1234-56789abcdef0
 */
static const uint8_t pqke_service_uuid_ad[16] = {
    0xf0, 0xde, 0xbc, 0x9a,
    0x78, 0x56,
    0x34, 0x12,
    0x78, 0x56,
    0x34, 0x12,
    0x78, 0x56, 0x34, 0x12
};

/*
 * Central chooses the initial connection parameters.
 *
 * interval unit = 1.25 ms
 * timeout unit  = 10 ms
 */
static const struct bt_le_conn_param pqke_conn_param = {
    .interval_min = 40,     
    .interval_max = 40,    
    .latency = 0,
    .timeout = 400,        /* 4 s */
};

static void start_scan(void);
static void discover_pqke_service(void);
static void discover_cp_characteristic(void);
static void discover_pk_characteristic(void);
static void discover_pk_ccc_descriptor(void);
static void discover_ct_characteristic(void);
static void discover_pqlvl_characteristic(void);
static void read_pqlvl(void);
static void subscribe_pk(void);
static void write_cp_init(void);

static void pqke_worker(void);
static int pqke_encapsulate(void);
static int write_ct_frames_blocking(void);
static int read_cp_blocking(uint8_t *value);
static int wait_for_decap_done_blocking(void);

K_THREAD_DEFINE(pqke_worker_tid,
                PQKE_WORKER_STACK_SIZE,
                pqke_worker,
                NULL, NULL, NULL,
                PQKE_WORKER_PRIORITY,
                0,
                0);

static void print_conn_params(struct bt_conn *conn, const char *tag)
{
    struct bt_conn_info info;
    const bt_addr_le_t *dst;
    char addr[BT_ADDR_LE_STR_LEN];
    int err;

    dst = bt_conn_get_dst(conn);
    if (dst) {
        bt_addr_le_to_str(dst, addr, sizeof(addr));
        printk("[%lld ms] [%s] peer=%s\n", k_uptime_get(), tag, addr);
    }

    err = bt_conn_get_info(conn, &info);
    if (err) {
        printk("[%lld ms] [%s] bt_conn_get_info failed: %d\n",
               k_uptime_get(), tag, err);
        return;
    }

    if (info.type != BT_CONN_TYPE_LE) {
        printk("[%lld ms] [%s] not an LE connection\n",
               k_uptime_get(), tag);
        return;
    }

    printk("[%lld ms] [%s] interval=%u units (%u.%02u ms), latency=%u, timeout=%u units (%u ms)\n",
           k_uptime_get(),
           tag,
           info.le.interval,
           (info.le.interval * 125) / 100,
           (info.le.interval * 125) % 100,
           info.le.latency,
           info.le.timeout,
           info.le.timeout * 10);
}

static bool ad_match_cb(struct bt_data *data, void *user_data)
{
    bool *matched = user_data;

    if (data->type == BT_DATA_UUID128_ALL ||
        data->type == BT_DATA_UUID128_SOME) {

        printk("[%lld ms] UUID128 data:", k_uptime_get());
        for (uint8_t i = 0; i < data->data_len; i++) {
            printk(" %02x", data->data[i]);
        }
        printk("\n");

        for (uint8_t off = 0; off + 16 <= data->data_len; off += 16) {
            if (memcmp(&data->data[off], pqke_service_uuid_ad, 16) == 0) {
                *matched = true;
                return false;
            }
        }
    }

    return true;
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi,
                         uint8_t adv_type, struct net_buf_simple *ad)
{
    char addr_str[BT_ADDR_LE_STR_LEN];
    bool matched = false;
    int err;

    if (default_conn || connecting) {
        return;
    }

    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

    // printk("[%lld ms] Scan result: addr=%s RSSI=%d type=0x%02x adv_len=%u\n",
    //        k_uptime_get(), addr_str, rssi, adv_type, ad->len);

    bt_data_parse(ad, ad_match_cb, &matched);

    if (!matched) {
        return;
    }

    printk("[%lld ms] PQKE service UUID matched. Connecting to %s...\n",
           k_uptime_get(), addr_str);

    connecting = true;
    scan_match_seen = true;

    err = bt_le_scan_stop();
    if (err) {
        printk("[%lld ms] Failed to stop scan: %d\n", k_uptime_get(), err);
        connecting = false;
        return;
    }

    err = bt_conn_le_create(addr,
                            BT_CONN_LE_CREATE_CONN,
                            &pqke_conn_param,
                            &default_conn);
    if (err) {
        printk("[%lld ms] Failed to create connection: %d\n",
               k_uptime_get(), err);
        default_conn = NULL;
        connecting = false;
        start_scan();
        return;
    }

    printk("[%lld ms] Connection pending...\n", k_uptime_get());
}

static void start_scan(void)
{
    struct bt_le_scan_param scan_param = {
        .type = BT_LE_SCAN_TYPE_ACTIVE,
        .options = BT_LE_SCAN_OPT_NONE,
        .interval = BT_GAP_SCAN_FAST_WINDOW * 4,
        .window = BT_GAP_SCAN_FAST_WINDOW,
    };

    int err;

    err = bt_le_scan_start(&scan_param, device_found);
    if (err) {
        printk("[%lld ms] Scanning failed to start: %d\n",
               k_uptime_get(), err);
        return;
    }

    printk("[%lld ms] Active scanning for PQKE service UUID...\n",
           k_uptime_get());
}

static void mtu_exchange_cb(struct bt_conn *conn, uint8_t err,
                            struct bt_gatt_exchange_params *params)
{
    printk("[%lld ms] MTU exchange %s, ATT MTU=%u\n",
           k_uptime_get(),
           err ? "failed" : "complete",
           bt_gatt_get_mtu(conn));

    discover_pqke_service();
}

static void connected(struct bt_conn *conn, uint8_t conn_err)
{
    char addr[BT_ADDR_LE_STR_LEN];
    int err;

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    connecting = false;

    if (conn_err) {
        printk("[%lld ms] Failed to connect to %s, err=0x%02x\n",
               k_uptime_get(), addr, conn_err);

        if (default_conn) {
            bt_conn_unref(default_conn);
            default_conn = NULL;
        }

        start_scan();
        return;
    }

    printk("[%lld ms] Connected: %s\n", k_uptime_get(), addr);
    print_conn_params(conn, "connected");

    mtu_exchange_params.func = mtu_exchange_cb;

    err = bt_gatt_exchange_mtu(conn, &mtu_exchange_params);
    if (err) {
        printk("[%lld ms] MTU exchange request failed: %d; continuing discovery\n",
               k_uptime_get(), err);
        discover_pqke_service();
    }
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    printk("[%lld ms] Disconnected, reason=0x%02x\n",
           k_uptime_get(), reason);

    if (default_conn) {
        bt_conn_unref(default_conn);
        default_conn = NULL;
    }

    svc_start_handle = 0;
    svc_end_handle = 0;
    cp_value_handle = 0;
    pk_value_handle = 0;
    pk_ccc_handle = 0;
    ct_value_handle = 0;
    pqlvl_value_handle = 0;

    pk_len = 0;
    expected_pk_len = 0;
    expected_ct_len = 0;
    ct_frame_len = 0;
    pqlvl = 0;
    pk_complete = false;
    pqke_worker_busy = false;
    connecting = false;

    start_scan();
}

static void le_param_updated(struct bt_conn *conn,
                             uint16_t interval,
                             uint16_t latency,
                             uint16_t timeout)
{
    printk("[%lld ms] [param update] interval=%u units (%u.%02u ms), latency=%u, timeout=%u units (%u ms)\n",
           k_uptime_get(),
           interval,
           (interval * 125) / 100,
           (interval * 125) % 100,
           latency,
           timeout,
           timeout * 10);
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
    .le_param_updated = le_param_updated,
};

static uint8_t discover_service_cb(struct bt_conn *conn,
                                   const struct bt_gatt_attr *attr,
                                   struct bt_gatt_discover_params *params)
{
    struct bt_gatt_service_val *svc;

    if (!attr) {
        printk("[%lld ms] PQKE service discovery failed\n", k_uptime_get());
        (void)memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }

    svc = attr->user_data;
    svc_start_handle = attr->handle + 1;
    svc_end_handle = svc->end_handle;

    printk("[%lld ms] PQKE service discovered: start=0x%04x end=0x%04x\n",
           k_uptime_get(), svc_start_handle, svc_end_handle);

    (void)memset(params, 0, sizeof(*params));
    discover_cp_characteristic();

    return BT_GATT_ITER_STOP;
}

static void discover_pqke_service(void)
{
    int err;

    if (!default_conn) {
        return;
    }

    printk("[%lld ms] Discovering PQKE primary service...\n",
           k_uptime_get());

    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid = &pqke_svc_uuid.uuid;
    discover_params.func = discover_service_cb;
    discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
    discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
    discover_params.type = BT_GATT_DISCOVER_PRIMARY;

    err = bt_gatt_discover(default_conn, &discover_params);
    if (err) {
        printk("[%lld ms] Service discovery request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t discover_cp_cb(struct bt_conn *conn,
                              const struct bt_gatt_attr *attr,
                              struct bt_gatt_discover_params *params)
{
    struct bt_gatt_chrc *chrc;

    if (!attr) {
        printk("[%lld ms] CP characteristic discovery failed\n",
               k_uptime_get());
        (void)memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }

    chrc = attr->user_data;
    cp_value_handle = chrc->value_handle;

    printk("[%lld ms] CP characteristic handle=0x%04x\n",
           k_uptime_get(), cp_value_handle);

    (void)memset(params, 0, sizeof(*params));
    discover_pk_characteristic();

    return BT_GATT_ITER_STOP;
}

static void discover_cp_characteristic(void)
{
    int err;

    printk("[%lld ms] Discovering CP characteristic...\n",
           k_uptime_get());

    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid = &cp_uuid.uuid;
    discover_params.func = discover_cp_cb;
    discover_params.start_handle = svc_start_handle;
    discover_params.end_handle = svc_end_handle;
    discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

    err = bt_gatt_discover(default_conn, &discover_params);
    if (err) {
        printk("[%lld ms] CP discovery request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t discover_pk_cb(struct bt_conn *conn,
                              const struct bt_gatt_attr *attr,
                              struct bt_gatt_discover_params *params)
{
    struct bt_gatt_chrc *chrc;

    if (!attr) {
        printk("[%lld ms] PK characteristic discovery failed\n",
               k_uptime_get());
        (void)memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }

    chrc = attr->user_data;
    pk_value_handle = chrc->value_handle;

    printk("[%lld ms] PK indication characteristic handle=0x%04x\n",
           k_uptime_get(), pk_value_handle);

    (void)memset(params, 0, sizeof(*params));
    discover_pk_ccc_descriptor();

    return BT_GATT_ITER_STOP;
}

static void discover_pk_characteristic(void)
{
    int err;

    printk("[%lld ms] Discovering PK indication characteristic...\n",
           k_uptime_get());

    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid = &pk_uuid.uuid;
    discover_params.func = discover_pk_cb;
    discover_params.start_handle = svc_start_handle;
    discover_params.end_handle = svc_end_handle;
    discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

    err = bt_gatt_discover(default_conn, &discover_params);
    if (err) {
        printk("[%lld ms] PK discovery request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t discover_pk_ccc_cb(struct bt_conn *conn,
                                  const struct bt_gatt_attr *attr,
                                  struct bt_gatt_discover_params *params)
{
    if (!attr) {
        printk("[%lld ms] PK CCC descriptor discovery failed\n",
               k_uptime_get());
        (void)memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }

    pk_ccc_handle = attr->handle;

    printk("[%lld ms] PK CCC descriptor handle=0x%04x\n",
           k_uptime_get(), pk_ccc_handle);

    (void)memset(params, 0, sizeof(*params));
    discover_ct_characteristic();

    return BT_GATT_ITER_STOP;
}

static void discover_pk_ccc_descriptor(void)
{
    int err;

    printk("[%lld ms] Discovering PK CCC descriptor...\n",
           k_uptime_get());

    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid = &ccc_uuid.uuid;
    discover_params.func = discover_pk_ccc_cb;
    discover_params.start_handle = pk_value_handle + 1;
    discover_params.end_handle = svc_end_handle;
    discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;

    err = bt_gatt_discover(default_conn, &discover_params);
    if (err) {
        printk("[%lld ms] PK CCC discovery request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t discover_ct_cb(struct bt_conn *conn,
                              const struct bt_gatt_attr *attr,
                              struct bt_gatt_discover_params *params)
{
    struct bt_gatt_chrc *chrc;

    if (!attr) {
        printk("[%lld ms] CT characteristic discovery failed\n",
               k_uptime_get());
        (void)memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }

    chrc = attr->user_data;
    ct_value_handle = chrc->value_handle;

    printk("[%lld ms] CT write characteristic handle=0x%04x\n",
           k_uptime_get(), ct_value_handle);

    (void)memset(params, 0, sizeof(*params));
    discover_pqlvl_characteristic();

    return BT_GATT_ITER_STOP;
}

static void discover_ct_characteristic(void)
{
    int err;

    printk("[%lld ms] Discovering CT write characteristic...\n",
           k_uptime_get());

    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid = &ct_uuid.uuid;
    discover_params.func = discover_ct_cb;
    discover_params.start_handle = svc_start_handle;
    discover_params.end_handle = svc_end_handle;
    discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

    err = bt_gatt_discover(default_conn, &discover_params);
    if (err) {
        printk("[%lld ms] CT discovery request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t discover_pqlvl_cb(struct bt_conn *conn,
                                 const struct bt_gatt_attr *attr,
                                 struct bt_gatt_discover_params *params)
{
    struct bt_gatt_chrc *chrc;

    if (!attr) {
        printk("[%lld ms] PQLVL characteristic discovery failed; defaulting to ML-KEM-512\n",
               k_uptime_get());

        pqlvl_value_handle = 0;
        pqlvl = 1;
        expected_pk_len = MLKEM512_PK_BYTES;
        expected_ct_len = MLKEM512_CT_BYTES;
        ct_frame_len = CT_FRAME_LEN_512;

        (void)memset(params, 0, sizeof(*params));
        subscribe_pk();

        return BT_GATT_ITER_STOP;
    }

    chrc = attr->user_data;
    pqlvl_value_handle = chrc->value_handle;

    printk("[%lld ms] PQLVL characteristic handle=0x%04x\n",
           k_uptime_get(), pqlvl_value_handle);

    (void)memset(params, 0, sizeof(*params));
    read_pqlvl();

    return BT_GATT_ITER_STOP;
}

static void discover_pqlvl_characteristic(void)
{
    int err;

    printk("[%lld ms] Discovering PQLVL characteristic...\n",
           k_uptime_get());

    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid = &pqlvl_uuid.uuid;
    discover_params.func = discover_pqlvl_cb;
    discover_params.start_handle = svc_start_handle;
    discover_params.end_handle = svc_end_handle;
    discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

    err = bt_gatt_discover(default_conn, &discover_params);
    if (err) {
        printk("[%lld ms] PQLVL discovery request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t pqlvl_read_cb(struct bt_conn *conn, uint8_t err,
                             struct bt_gatt_read_params *params,
                             const void *data, uint16_t length)
{
    if (err || !data || length < 1) {
        printk("[%lld ms] PQLVL read failed/empty; defaulting to ML-KEM-512\n",
               k_uptime_get());
        pqlvl = 1;
    } else {
        pqlvl = ((const uint8_t *)data)[0];
    }

    switch (pqlvl) {
    case 1:
        expected_pk_len = MLKEM512_PK_BYTES;
        expected_ct_len = MLKEM512_CT_BYTES;
        ct_frame_len = CT_FRAME_LEN_512;
        break;
    case 3:
        expected_pk_len = MLKEM768_PK_BYTES;
        expected_ct_len = MLKEM768_CT_BYTES;
        ct_frame_len = CT_FRAME_LEN_768;
        break;
    case 5:
        expected_pk_len = MLKEM1024_PK_BYTES;
        expected_ct_len = MLKEM1024_CT_BYTES;
        ct_frame_len = CT_FRAME_LEN_1024;
        break;
    default:
        printk("[%lld ms] Unknown PQLVL=0x%02x; defaulting to ML-KEM-512\n",
               k_uptime_get(), pqlvl);
        pqlvl = 1;
        expected_pk_len = MLKEM512_PK_BYTES;
        expected_ct_len = MLKEM512_CT_BYTES;
        ct_frame_len = CT_FRAME_LEN_512;
        break;
    }

    printk("[%lld ms] PQLVL=0x%02x, PK=%u bytes, CT=%u bytes, CT_FRAME_LEN=%u\n",
           k_uptime_get(),
           pqlvl,
           (unsigned int)expected_pk_len,
           (unsigned int)expected_ct_len,
           (unsigned int)ct_frame_len);

    subscribe_pk();

    return BT_GATT_ITER_STOP;
}

static void read_pqlvl(void)
{
    int err;

    printk("[%lld ms] Reading PQLVL...\n", k_uptime_get());

    memset(&read_params, 0, sizeof(read_params));
    read_params.func = pqlvl_read_cb;
    read_params.handle_count = 1;
    read_params.single.handle = pqlvl_value_handle;
    read_params.single.offset = 0;

    err = bt_gatt_read(default_conn, &read_params);
    if (err) {
        printk("[%lld ms] PQLVL read request failed: %d\n",
               k_uptime_get(), err);
    }
}

static uint8_t pk_indicate_cb(struct bt_conn *conn,
                              struct bt_gatt_subscribe_params *params,
                              const void *data, uint16_t length)
{
    size_t room;
    size_t copy_len;

    if (!data) {
        printk("[%lld ms] PK indication subscription ended\n",
               k_uptime_get());
        return BT_GATT_ITER_STOP;
    }

    if (pk_complete) {
        printk("[%lld ms] Extra PK indication ignored: %u bytes\n",
               k_uptime_get(), length);
        return BT_GATT_ITER_CONTINUE;
    }

    room = PK_BUF_MAX - pk_len;
    copy_len = length < room ? length : room;

    memcpy(&pk_buf[pk_len], data, copy_len);
    pk_len += copy_len;

    printk("[%lld ms] PK indication: fragment=%u bytes, copied=%u, total=%u/%u\n",
           k_uptime_get(),
           length,
           (unsigned int)copy_len,
           (unsigned int)pk_len,
           (unsigned int)expected_pk_len);

    if (copy_len < length) {
        printk("[%lld ms] WARNING: PK buffer full; truncated %u bytes\n",
               k_uptime_get(), (unsigned int)(length - copy_len));
    }

    if (expected_pk_len > 0 && pk_len >= expected_pk_len) {
        pk_complete = true;

        printk("[%lld ms] FULL PUBLIC KEY RECEIVED: %u bytes\n",
               k_uptime_get(), (unsigned int)pk_len);

        printk("[%lld ms] First 16 PK bytes:", k_uptime_get());
        for (size_t i = 0; i < 16 && i < pk_len; i++) {
            printk(" %02x", pk_buf[i]);
        }
        printk("\n");

        printk("[%lld ms] Signalling PQKE worker for encapsulation\n",
               k_uptime_get());

        k_sem_give(&pk_ready_sem);
    }

    return BT_GATT_ITER_CONTINUE;
}

static void subscribe_pk(void)
{
    int err;

    printk("[%lld ms] Subscribing to PK indication: value_handle=0x%04x ccc_handle=0x%04x\n",
           k_uptime_get(), pk_value_handle, pk_ccc_handle);

    if (!pk_value_handle || !pk_ccc_handle) {
        printk("[%lld ms] Cannot subscribe: missing PK value or CCC handle\n",
               k_uptime_get());
        return;
    }

    memset(&pk_subscribe_params, 0, sizeof(pk_subscribe_params));
    pk_subscribe_params.notify = pk_indicate_cb;
    pk_subscribe_params.value = BT_GATT_CCC_INDICATE;
    pk_subscribe_params.value_handle = pk_value_handle;
    pk_subscribe_params.ccc_handle = pk_ccc_handle;

    err = bt_gatt_subscribe(default_conn, &pk_subscribe_params);
    if (err && err != -EALREADY) {
        printk("[%lld ms] PK subscribe failed: %d\n",
               k_uptime_get(), err);
        return;
    }

    printk("[%lld ms] PK indication subscribed\n", k_uptime_get());

    pk_len = 0;
    pk_complete = false;
    pqke_worker_busy = false;

    write_cp_init();
}

static void cp_write_cb(struct bt_conn *conn, uint8_t err,
                        struct bt_gatt_write_params *params)
{
    if (err) {
        printk("[%lld ms] CP_INIT write failed: 0x%02x\n",
               k_uptime_get(), err);
        return;
    }

    printk("[%lld ms] CP_INIT write complete; waiting for PK indications...\n",
           k_uptime_get());
}

static void write_cp_init(void)
{
    static uint8_t cmd = CP_INIT;
    int err;

    printk("[%lld ms] Writing CP_INIT=0x%02x to handle=0x%04x\n",
           k_uptime_get(), cmd, cp_value_handle);

    memset(&write_params, 0, sizeof(write_params));
    write_params.func = cp_write_cb;
    write_params.handle = cp_value_handle;
    write_params.offset = 0;
    write_params.data = &cmd;
    write_params.length = sizeof(cmd);

    err = bt_gatt_write(default_conn, &write_params);
    if (err) {
        printk("[%lld ms] CP_INIT write request failed: %d\n",
               k_uptime_get(), err);
    }
}

static int pqke_encapsulate(void)
{
    int ret = -EINVAL;
    int64_t t0;
    int64_t t1;

    if (pk_len < expected_pk_len) {
        printk("[%lld ms] Cannot encapsulate: pk_len=%u expected=%u\n",
               k_uptime_get(),
               (unsigned int)pk_len,
               (unsigned int)expected_pk_len);
        return -EINVAL;
    }

    printk("[%lld ms] ML-KEM encapsulation start: level=0x%02x\n",
           k_uptime_get(), pqlvl);

    t0 = k_uptime_get();

    switch (pqlvl) {
    case 1:
        ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct_buf, ss_buf, pk_buf);
        break;
#if defined(PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES)
    case 3:
        ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct_buf, ss_buf, pk_buf);
        break;
#endif
#if defined(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES)
    case 5:
        ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct_buf, ss_buf, pk_buf);
        break;
#endif
    default:
        printk("[%lld ms] Unsupported PQLVL=0x%02x\n",
               k_uptime_get(), pqlvl);
        return -EINVAL;
    }

    t1 = k_uptime_get();

    printk("[%lld ms] ML-KEM encapsulation done: ret=%d duration=%lld ms\n",
           k_uptime_get(), ret, t1 - t0);

    if (ret != 0) {
        return ret;
    }

    printk("[%lld ms] First 16 CT bytes:", k_uptime_get());
    for (size_t i = 0; i < 16 && i < expected_ct_len; i++) {
        printk(" %02x", ct_buf[i]);
    }
    printk("\n");

    printk("[%lld ms] First 16 SS bytes:", k_uptime_get());
    for (size_t i = 0; i < 16 && i < SS_BYTES; i++) {
        printk(" %02x", ss_buf[i]);
    }
    printk("\n");

    return 0;
}

/*
 * Blocking write completion.
 *
 * This is called from the PQKE worker thread, not from a Bluetooth callback.
 */
K_SEM_DEFINE(gatt_write_sem, 0, 1);
static volatile uint8_t gatt_write_err;

static void generic_write_cb(struct bt_conn *conn, uint8_t err,
                             struct bt_gatt_write_params *params)
{
    gatt_write_err = err;
    k_sem_give(&gatt_write_sem);
}

static int write_gatt_blocking(uint16_t handle, const uint8_t *data, uint16_t len)
{
    static struct bt_gatt_write_params params;
    int err;

    memset(&params, 0, sizeof(params));

    gatt_write_err = 0;

    params.func = generic_write_cb;
    params.handle = handle;
    params.offset = 0;
    params.data = data;
    params.length = len;

    err = bt_gatt_write(default_conn, &params);
    if (err) {
        printk("[%lld ms] bt_gatt_write request failed: %d\n",
               k_uptime_get(), err);
        return err;
    }

    if (k_sem_take(&gatt_write_sem, K_SECONDS(10)) != 0) {
        printk("[%lld ms] bt_gatt_write timeout\n", k_uptime_get());
        return -ETIMEDOUT;
    }

    if (gatt_write_err) {
        printk("[%lld ms] bt_gatt_write completed with ATT err=0x%02x\n",
               k_uptime_get(), gatt_write_err);
        return -EIO;
    }

    return 0;
}

static int write_ct_frames_blocking(void)
{
    uint8_t frame[CT_FRAME_LEN_1024];
    size_t payload_len;
    size_t sent = 0;
    uint8_t frame_no = 0;
    int err;
    int64_t t0;
    int64_t t1;

    if (!ct_value_handle) {
        printk("[%lld ms] Cannot write CT: missing CT handle\n",
               k_uptime_get());
        return -EINVAL;
    }

    if (ct_frame_len == 0 || ct_frame_len > sizeof(frame)) {
        printk("[%lld ms] Invalid CT frame length: %u\n",
               k_uptime_get(), (unsigned int)ct_frame_len);
        return -EINVAL;
    }

    payload_len = ct_frame_len - 1U;

    printk("[%lld ms] CT write start: CT=%u bytes, frame_len=%u, payload/frame=%u\n",
           k_uptime_get(),
           (unsigned int)expected_ct_len,
           (unsigned int)ct_frame_len,
           (unsigned int)payload_len);

    t0 = k_uptime_get();

    while (sent < expected_ct_len) {
        size_t remaining = expected_ct_len - sent;
        size_t chunk = remaining < payload_len ? remaining : payload_len;

        memset(frame, 0, ct_frame_len);
        memcpy(frame, &ct_buf[sent], chunk);
        frame[ct_frame_len - 1] = frame_no;

        /*
         * Write full frame length to match the original peripheral-side frame logic.
         */
        err = write_gatt_blocking(ct_value_handle, frame, ct_frame_len);
        if (err) {
            printk("[%lld ms] CT frame %u write failed: %d\n",
                   k_uptime_get(), frame_no, err);
            return err;
        }

        sent += chunk;

        printk("[%lld ms] CT frame %u written: chunk=%u, sent=%u/%u\n",
               k_uptime_get(),
               frame_no,
               (unsigned int)chunk,
               (unsigned int)sent,
               (unsigned int)expected_ct_len);

        frame_no++;
        k_sleep(K_MSEC(5));
    }

    t1 = k_uptime_get();

    printk("[%lld ms] CT write complete: frames=%u duration=%lld ms\n",
           k_uptime_get(), frame_no, t1 - t0);

    return 0;
}

/*
 * Blocking read completion for CP polling.
 */
K_SEM_DEFINE(gatt_read_sem, 0, 1);
static volatile uint8_t gatt_read_err;
static uint8_t cp_read_value;

static uint8_t cp_read_cb(struct bt_conn *conn, uint8_t err,
                          struct bt_gatt_read_params *params,
                          const void *data, uint16_t length)
{
    gatt_read_err = err;

    if (!err && data && length >= 1) {
        cp_read_value = ((const uint8_t *)data)[0];
    }

    k_sem_give(&gatt_read_sem);

    return BT_GATT_ITER_STOP;
}

static int read_cp_blocking(uint8_t *value)
{
    static struct bt_gatt_read_params params;
    int err;

    memset(&params, 0, sizeof(params));

    gatt_read_err = 0;
    cp_read_value = 0;

    params.func = cp_read_cb;
    params.handle_count = 1;
    params.single.handle = cp_value_handle;
    params.single.offset = 0;

    err = bt_gatt_read(default_conn, &params);
    if (err) {
        printk("[%lld ms] bt_gatt_read CP request failed: %d\n",
               k_uptime_get(), err);
        return err;
    }

    if (k_sem_take(&gatt_read_sem, K_SECONDS(5)) != 0) {
        printk("[%lld ms] bt_gatt_read CP timeout\n", k_uptime_get());
        return -ETIMEDOUT;
    }

    if (gatt_read_err) {
        printk("[%lld ms] bt_gatt_read CP completed with ATT err=0x%02x\n",
               k_uptime_get(), gatt_read_err);
        return -EIO;
    }

    *value = cp_read_value;
    return 0;
}

static int wait_for_decap_done_blocking(void)
{
    int err;
    uint8_t cp;
    int64_t start = k_uptime_get();

    printk("[%lld ms] Polling CP for decapsulation completion...\n",
           k_uptime_get());

    while (k_uptime_get() - start < 30000) {
        err = read_cp_blocking(&cp);
        if (err) {
            return err;
        }

        printk("[%lld ms] CP read: 0x%02x\n", k_uptime_get(), cp);

        if (cp == CP_DECAP_DONE) {
            printk("[%lld ms] CP_DECAP_DONE observed\n", k_uptime_get());
            return 0;
        }

        if (cp == CP_ERROR) {
            printk("[%lld ms] Peripheral reported CP_ERROR\n", k_uptime_get());
            return -EIO;
        }

        k_sleep(K_MSEC(200));
    }

    printk("[%lld ms] Timeout waiting for CP_DECAP_DONE\n", k_uptime_get());
    return -ETIMEDOUT;
}

static void pqke_worker(void)
{
    int err;

    while (1) {
        k_sem_take(&pk_ready_sem, K_FOREVER);

        if (pqke_worker_busy) {
            printk("[%lld ms] PQKE worker already busy; ignoring duplicate signal\n",
                   k_uptime_get());
            continue;
        }

        pqke_worker_busy = true;

        printk("[%lld ms] PQKE worker woke up\n", k_uptime_get());

        if (!default_conn) {
            printk("[%lld ms] No active connection; worker aborting\n",
                   k_uptime_get());
            pqke_worker_busy = false;
            continue;
        }

        if (!pk_complete || pk_len < expected_pk_len) {
            printk("[%lld ms] PK incomplete; pk_len=%u expected=%u\n",
                   k_uptime_get(),
                   (unsigned int)pk_len,
                   (unsigned int)expected_pk_len);
            pqke_worker_busy = false;
            continue;
        }

        err = pqke_encapsulate();
        if (err) {
            printk("[%lld ms] Encapsulation failed: %d\n",
                   k_uptime_get(), err);
            pqke_worker_busy = false;
            continue;
        }

        err = write_ct_frames_blocking();
        if (err) {
            printk("[%lld ms] CT write failed: %d\n",
                   k_uptime_get(), err);
            pqke_worker_busy = false;
            continue;
        }

        err = wait_for_decap_done_blocking();
        if (err) {
            printk("[%lld ms] Session did not complete cleanly: %d\n",
                   k_uptime_get(), err);
            pqke_worker_busy = false;
            continue;
        }

        printk("[%lld ms] CONNECTION-PQKE COMPLETE\n", k_uptime_get());

        pqke_worker_busy = false;
    }
}

int main(void)
{
    int err;

    printk("\n=== connection-PQKE central / gateway full test ===\n");

    err = bt_enable(NULL);
    if (err) {
        printk("Bluetooth init failed: %d\n", err);
        return 0;
    }

    printk("[%lld ms] Bluetooth initialized\n", k_uptime_get());

    start_scan();

    while (1) {
        k_sleep(K_SECONDS(5));

        if (!scan_match_seen && !default_conn && !connecting) {
            printk("[%lld ms] Still scanning; no PQKE service match yet\n",
                   k_uptime_get());
        }
    }

    return 0;
}