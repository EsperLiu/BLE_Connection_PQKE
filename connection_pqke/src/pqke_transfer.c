#include "pqke_transfer.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/bluetooth/gatt.h>

#include "ble_service.h"
#include "opcodes.h"
#include "pqke_config.h"
#include "pqke_crypto.h"
#include "pqke_state.h"

#define LOG(fmt, ...) \
    printk("[%8u ms] [XFER] " fmt "\n", (uint32_t)k_uptime_get(), ##__VA_ARGS__)

/*
 * Declared here to keep this experiment self-contained even if ble_service.h
 * has not yet been updated. Prefer moving this declaration into ble_service.h.
 */
bool ble_service_has_connection(void);

static uint8_t ct_frame[PQKE_CT_FRAME_LEN];
static struct bt_gatt_indicate_params pk_ind_params;
static bool indicating;
static bool ct_rx_started;
static uint32_t ct_rx_start_ms;

static void indicate_cb(struct bt_conn *conn, struct bt_gatt_indicate_params *params, uint8_t err)
{
    ARG_UNUSED(conn);
    ARG_UNUSED(params);

    if (err != 0U) {
        LOG("PK indication confirmation failed: err=%u", err);
    } else {
        LOG("PK indication confirmed by peer");
    }
}

static void indicate_destroy(struct bt_gatt_indicate_params *params)
{
    ARG_UNUSED(params);
    indicating = false;
}

int pqke_transfer_deliver_public_key(void)
{
    const uint8_t *pk = pqke_crypto_public_key();
    size_t remain_bytes = pqke_crypto_public_key_len();
    size_t total_len = remain_bytes;
    const struct bt_gatt_attr *ind_attr = ble_service_public_key_indicate_attr();
    uint32_t start_ms = (uint32_t)k_uptime_get();
    unsigned int chunk_no = 0;

    if (!ind_attr) {
        LOG("public-key indication characteristic not found");
        return -ENOENT;
    }

    LOG("public-key transfer begin: total=%u max_chunk=%u",
        (unsigned int)total_len, (unsigned int)PQKE_MAX_CHRC_BYTE);

    pk_ind_params.attr = ind_attr;
    pk_ind_params.func = indicate_cb;
    pk_ind_params.destroy = indicate_destroy;

    while (remain_bytes > 0) {
        if (indicating) {
            if (!ble_service_has_connection()) {
                LOG("PK indication aborted while waiting: no active connection");
                indicating = false;
                return -ENOTCONN;
            }

            k_msleep(10);
            continue;
        }

        if (!ble_service_has_connection()) {
            LOG("PK indication aborted before submit: no active connection");
            indicating = false;
            return -ENOTCONN;
        }

        size_t offset = total_len - remain_bytes;
        size_t chunk_len = MIN(remain_bytes, (size_t)PQKE_MAX_CHRC_BYTE);

        pk_ind_params.data = &pk[offset];
        pk_ind_params.len = chunk_len;

        int ret = bt_gatt_indicate(NULL, &pk_ind_params);
        if (ret == 0) {
            chunk_no++;
            LOG("PK indication submitted: chunk=%u offset=%u len=%u remaining_after=%u",
                chunk_no, (unsigned int)offset, (unsigned int)chunk_len,
                (unsigned int)(remain_bytes - chunk_len));
            indicating = true;
            remain_bytes -= chunk_len;
        } else {
            LOG("PK indication submit failed: err=%d", ret);

            if (!ble_service_has_connection() ||
                ret == -ENOTCONN || ret == -ECONNRESET || ret == -ESHUTDOWN) {
                LOG("PK indication aborted because connection is gone");
                indicating = false;
                return ret;
            }

            LOG("retrying PK indication");
            k_msleep(10);
        }
    }

    while (indicating) {
        if (!ble_service_has_connection()) {
            LOG("PK indication wait aborted: no active connection");
            indicating = false;
            return -ENOTCONN;
        }

        k_msleep(10);
    }

    LOG("public-key transfer complete: total=%u chunks=%u duration=%u ms",
        (unsigned int)total_len, chunk_no, (uint32_t)k_uptime_get() - start_ms);

    return 0;
}

ssize_t pqke_transfer_write_ciphertext_frame(const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
    if (!ct_rx_started) {
        ct_rx_started = true;
        ct_rx_start_ms = (uint32_t)k_uptime_get();
        LOG("ciphertext receive begin: ct_len=%u frames=%u frame_len=%u",
            (unsigned int)pqke_crypto_ciphertext_len(),
            (unsigned int)PQKE_CT_FRAMES,
            (unsigned int)PQKE_CT_FRAME_LEN);
    }

    if (flags & BT_GATT_WRITE_FLAG_PREPARE) {
        LOG("prepare-write fragment accepted: len=%u offset=%u flags=0x%02x", len, offset, flags);
        return 0;
    }

    if (offset + len > sizeof(ct_frame)) {
        LOG("CT write rejected: offset=%u len=%u frame_len=%u", offset, len,
            (unsigned int)sizeof(ct_frame));
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    memcpy(ct_frame + offset, buf, len);
    LOG("CT frame buffer updated: offset=%u len=%u end=%u", offset, len, offset + len);

    /*
     * Compatibility mode for the original client: each frame carries CT payload
     * followed by one frame-number byte. The final write of a frame is detected
     * using the old offset + len + 64 >= frame_len heuristic.
     */
    if (offset + len + 64 >= sizeof(ct_frame)) {
        uint8_t ct_frame_no = ct_frame[offset + len - 1];
        LOG("CT frame boundary detected: frame_no=%u", ct_frame_no);

        if (ct_frame_no >= PQKE_CT_FRAMES) {
            LOG("invalid CT frame number: %u", ct_frame_no);
            return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
        }

        uint8_t *ct = pqke_crypto_ciphertext_buffer();
        size_t ct_len = pqke_crypto_ciphertext_len();
        size_t frame_payload_len = PQKE_CT_FRAME_LEN - 1;
        size_t dst_offset = ct_frame_no * frame_payload_len;

        if (dst_offset >= ct_len) {
            LOG("invalid CT destination offset: frame_no=%u dst_offset=%u ct_len=%u",
                ct_frame_no, (unsigned int)dst_offset, (unsigned int)ct_len);
            return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
        }

        size_t remaining = ct_len - dst_offset;
        size_t copy_len = MIN(frame_payload_len, remaining);

        memcpy(ct + dst_offset, ct_frame, copy_len);
        LOG("CT frame copied: frame=%u dst_offset=%u copy_len=%u remaining_after=%u",
            ct_frame_no, (unsigned int)dst_offset, (unsigned int)copy_len,
            (unsigned int)(remaining - copy_len));

        if (ct_frame_no == PQKE_CT_FRAMES - 1) {
            LOG("last CT frame received; queuing CP_C_RECEIVED/CT_DONE; rx_duration=%u ms",
                (uint32_t)k_uptime_get() - ct_rx_start_ms);
            ct_rx_started = false;
            pqke_state_set_cp(CP_C_RECEIVED);
        }
    }

    return len;
}
