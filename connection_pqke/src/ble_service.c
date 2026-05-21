#include "ble_service.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>

#include "opcodes.h"
#include "pqke_config.h"
#include "pqke_crypto.h"
#include "pqke_state.h"
#include "pqke_transfer.h"

#define LOG(fmt, ...) \
    printk("[%8u ms] [BLE] " fmt "\n", (uint32_t)k_uptime_get(), ##__VA_ARGS__)

#define DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

#define BT_UUID_CUSTOM_SERVICE_VAL \
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcdef0)

static const uint8_t pqke_service_uuid_ad[16] = {
    0xf0, 0xde, 0xbc, 0x9a,
    0x78, 0x56,
    0x34, 0x12,
    0x78, 0x56,
    0x34, 0x12,
    0x78, 0x56, 0x34, 0x12
};


static struct bt_conn *current_conn;
static uint8_t ind_data = 1U;
static bool advertising_active;

/*
 * Radio/contact intermittence experiment.
 * The peripheral is only radio-available during RADIO_ACTIVE_WINDOW_MS.
 * At the end of each active window, advertising is stopped and any active
 * connection is forcibly disconnected. RAM is preserved; CPQKE session state
 * is reset because CPQKE is connection-bound and atomic.
 */
#define RADIO_ACTIVE_WINDOW_MS    60000
#define RADIO_INACTIVE_WINDOW_MS  0

static bool radio_window_open;
static struct k_work_delayable radio_window_end_work;
static struct k_work_delayable radio_window_start_work;

static struct bt_uuid_128 vnd_uuid = BT_UUID_INIT_128(BT_UUID_CUSTOM_SERVICE_VAL);

static const struct bt_uuid_128 cp_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde01));

static const struct bt_uuid_128 ind_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde02));

static const struct bt_uuid_128 ct_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde03));

static const struct bt_uuid_128 pqlvl_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcde04));

static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_CUSTOM_SERVICE_VAL),
};

static const struct bt_data sd[] = {
    BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static const struct bt_le_adv_param adv_params = {
    .options = BT_LE_ADV_OPT_CONN,
    .interval_min = PQKE_ADV_INTERVAL_MIN,
    .interval_max = PQKE_ADV_INTERVAL_MAX,
    .id = BT_ID_DEFAULT,
    .sid = 0,
};

static const struct bt_le_conn_param pqke_conn_param = {
    .interval_min = PQKE_CONN_INTERVAL_MIN,
    .interval_max = PQKE_CONN_INTERVAL_MAX,
    .latency = PQKE_CONN_LATENCY,
    .timeout = PQKE_CONN_TIMEOUT,
};

static bool ad_match_cb(struct bt_data *data, void *user_data)
{
    bool *matched = user_data;

    if (data->type == BT_DATA_UUID128_ALL ||
        data->type == BT_DATA_UUID128_SOME) {

        for (uint8_t off = 0; off + 16 <= data->data_len; off += 16) {
            if (memcmp(&data->data[off], pqke_service_uuid_ad, 16) == 0) {
                *matched = true;
                return false;
            }
        }
    }

    return true;
}

static int start_advertising(void)
{
    int err;

    if (advertising_active) {
        LOG("advertising already active");
        return 0;
    }

    LOG("starting advertising: name=%s, adv_int=[%u,%u] units", DEVICE_NAME,
        adv_params.interval_min, adv_params.interval_max);

    err = bt_le_adv_start(&adv_params, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
    if (err) {
        LOG("advertising failed to start: err=%d", err);
        return err;
    }

    advertising_active = true;
    LOG("advertising started; service UUID advertised, name in scan response");
    return 0;
}

static int stop_advertising(void)
{
    int err;

    if (!advertising_active) {
        LOG("advertising already inactive");
        return 0;
    }

    LOG("stopping advertising");

    err = bt_le_adv_stop();
    if (err) {
        LOG("advertising stop failed: err=%d", err);
        return err;
    }

    advertising_active = false;
    LOG("advertising stopped");
    return 0;
}

static ssize_t read_cp(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                       void *buf, uint16_t len, uint16_t offset)
{
    ARG_UNUSED(conn);
    ARG_UNUSED(attr);

    uint8_t value = pqke_state_get_cp();
    LOG("CP read: value=0x%02x len=%u offset=%u", value, len, offset);
    return bt_gatt_attr_read(conn, attr, buf, len, offset, &value, sizeof(value));
}

static ssize_t read_pqlvl(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                          void *buf, uint16_t len, uint16_t offset)
{
    ARG_UNUSED(attr);

    static const uint8_t level = MLKEM_SEC_LEVEL;
    LOG("PQLVL read: level=0x%02x len=%u offset=%u", level, len, offset);
    return bt_gatt_attr_read(conn, attr, buf, len, offset, &level, sizeof(level));
}

static ssize_t write_cp(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, uint16_t len, uint16_t offset,
                        uint8_t flags)
{
    ARG_UNUSED(conn);
    ARG_UNUSED(attr);

    LOG("CP write request: len=%u offset=%u flags=0x%02x", len, offset, flags);

    if (offset != 0 || len != 1) {
        LOG("CP write rejected: expected len=1 offset=0");
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    uint8_t value;
    memcpy(&value, buf, sizeof(value));
    LOG("CP write value: 0x%02x", value);
    pqke_state_set_cp(value);
    return len;
}

static ssize_t write_ct(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, uint16_t len, uint16_t offset,
                        uint8_t flags)
{
    ARG_UNUSED(conn);
    ARG_UNUSED(attr);

    LOG("CT write request: len=%u offset=%u flags=0x%02x", len, offset, flags);
    return pqke_transfer_write_ciphertext_frame(buf, len, offset, flags);
}

static void ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
    ARG_UNUSED(attr);

    LOG("CCC changed: value=0x%04x", value);
}

static struct bt_gatt_cep ct_cep = {
    .properties = BT_GATT_CEP_RELIABLE_WRITE,
};

BT_GATT_SERVICE_DEFINE(vnd_svc,
    BT_GATT_PRIMARY_SERVICE(&vnd_uuid),
    BT_GATT_CHARACTERISTIC(&cp_uuid.uuid,
        BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_WRITE,
        BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
        read_cp, write_cp, NULL),
    BT_GATT_CCC(ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
    BT_GATT_CHARACTERISTIC(&ind_uuid.uuid,
        BT_GATT_CHRC_READ | BT_GATT_CHRC_INDICATE,
        BT_GATT_PERM_READ,
        read_cp, NULL, &ind_data),
    BT_GATT_CCC(ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
    BT_GATT_CHARACTERISTIC(&ct_uuid.uuid,
        BT_GATT_CHRC_WRITE | BT_GATT_CHRC_EXT_PROP,
        BT_GATT_PERM_WRITE | BT_GATT_PERM_PREPARE_WRITE,
        NULL, write_ct, NULL),
    BT_GATT_CEP(&ct_cep),
    BT_GATT_CHARACTERISTIC(&pqlvl_uuid.uuid,
        BT_GATT_CHRC_READ,
        BT_GATT_PERM_READ,
        read_pqlvl, NULL, NULL),
);

static void mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
    LOG("MTU updated: TX=%u RX=%u ATT_MTU=%u", tx, rx, bt_gatt_get_mtu(conn));
}

static struct bt_gatt_cb gatt_callbacks = {
    .att_mtu_updated = mtu_updated,
};

static void radio_window_end_handler(struct k_work *work)
{
    ARG_UNUSED(work);

    radio_window_open = false;

    LOG("RADIO WINDOW END: active=%u ms; cutting advertising and connection",
        RADIO_ACTIVE_WINDOW_MS);

    (void)stop_advertising();

    if (current_conn) {
        int ret;

        LOG("disconnecting active CPQKE connection due to radio window end");
        ret = bt_conn_disconnect(current_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        if (ret) {
            LOG("bt_conn_disconnect failed: err=%d", ret);
        }
    }

    k_work_schedule(&radio_window_start_work,
                    K_MSEC(RADIO_INACTIVE_WINDOW_MS));
}

static void radio_window_start_handler(struct k_work *work)
{
    int err;

    ARG_UNUSED(work);

    radio_window_open = true;

    LOG("RADIO WINDOW START: advertising for %u ms", RADIO_ACTIVE_WINDOW_MS);

    pqke_state_reset_to_idle_no_notify();

    err = start_advertising();
    if (err) {
        LOG("radio window start failed to start advertising: err=%d", err);
    }

    k_work_schedule(&radio_window_end_work,
                    K_MSEC(RADIO_ACTIVE_WINDOW_MS));
}

static void connected(struct bt_conn *conn, uint8_t err)
{
    int ret;

    if (err) {
        LOG("connection failed: err=0x%02x", err);
        return;
    }

    advertising_active = false;

    if (!radio_window_open) {
        LOG("connected outside radio window; disconnecting immediately");
        (void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        return;
    }

    LOG("connected; ATT_MTU=%u", bt_gatt_get_mtu(conn));

    if (current_conn) {
        bt_conn_unref(current_conn);
    }
    current_conn = bt_conn_ref(conn);

    ret = bt_conn_le_param_update(conn, &pqke_conn_param);
    if (ret) {
        LOG("connection parameter update request failed: err=%d", ret);
    } else {
        LOG("connection parameter update requested: interval=[%u,%u], latency=%u, timeout=%u",
            pqke_conn_param.interval_min, pqke_conn_param.interval_max,
            pqke_conn_param.latency, pqke_conn_param.timeout);
    }
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    ARG_UNUSED(conn);

    LOG("disconnected: reason=0x%02x", reason);

    if (current_conn) {
        bt_conn_unref(current_conn);
        current_conn = NULL;
    }

    pqke_state_reset_to_idle_no_notify();

    if (radio_window_open) {
        LOG("radio window still open; restarting advertising");
        (void)start_advertising();
    } else {
        LOG("radio window closed; advertising remains off");
    }
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
};

int ble_service_notify_cp(uint8_t value)
{
    if (!current_conn) {
        LOG("CP notify skipped: no active connection, value=0x%02x", value);
        return -ENOTCONN;
    }

    LOG("CP notify: value=0x%02x", value);
    int ret = bt_gatt_notify_uuid(current_conn, &cp_uuid.uuid, vnd_svc.attrs,
                                  &value, sizeof(value));
    if (ret) {
        LOG("CP notify failed: err=%d", ret);
    }
    return ret;
}

bool ble_service_has_connection(void)
{
    return current_conn != NULL;
}

int ble_service_disconnect(void)
{
    if (!current_conn) {
        LOG("disconnect requested but no active connection");
        return -ENOTCONN;
    }

    LOG("disconnect requested by protocol");
    return bt_conn_disconnect(current_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

const struct bt_gatt_attr *ble_service_public_key_indicate_attr(void)
{
    const struct bt_gatt_attr *attr;

    attr = bt_gatt_find_by_uuid(vnd_svc.attrs, vnd_svc.attr_count, &ind_uuid.uuid);
    if (!attr) {
        LOG("PK indication attribute lookup failed");
    }
    return attr;
}

int ble_service_init(void)
{
    int err;

    LOG("initialising connection-PQKE BLE service");
    LOG("KEM level=%u pk_len=%u ct_len=%u ct_frames=%u ct_frame_len=%u",
        MLKEM_SEC_LEVEL, (unsigned int)PQKE_PK_BYTES, (unsigned int)PQKE_CT_BYTES,
        (unsigned int)PQKE_CT_FRAMES, (unsigned int)PQKE_CT_FRAME_LEN);

    if (IS_ENABLED(CONFIG_SETTINGS)) {
        err = settings_load();
        if (err) {
            LOG("settings_load failed: err=%d", err);
        } else {
            LOG("settings loaded");
        }
    }

    bt_gatt_cb_register(&gatt_callbacks);
    LOG("GATT callbacks registered");

    k_work_init_delayable(&radio_window_end_work, radio_window_end_handler);
    k_work_init_delayable(&radio_window_start_work, radio_window_start_handler);

    radio_window_open = true;

    err = start_advertising();
    if (err) {
        return err;
    }

    k_work_schedule(&radio_window_end_work,
                    K_MSEC(RADIO_ACTIVE_WINDOW_MS));

    LOG("radio intermittence enabled: active=%u ms inactive=%u ms",
        RADIO_ACTIVE_WINDOW_MS, RADIO_INACTIVE_WINDOW_MS);

    return 0;
}
