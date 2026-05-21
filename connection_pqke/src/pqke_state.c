#include "pqke_state.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "ble_service.h"
#include "opcodes.h"
#include "pqke_config.h"
#include "pqke_crypto.h"
#include "pqke_transfer.h"

#define LOG(fmt, ...) \
    printk("[%8u ms] [STATE] " fmt "\n", (uint32_t)k_uptime_get(), ##__VA_ARGS__)

K_SEM_DEFINE(cp_sem, 0, 1);

static uint8_t cp = CP_IDLE;

static const char *cp_name(uint8_t value)
{
    switch (value) {
    case CP_IDLE: return "CP_IDLE";
    case CP_PING: return "CP_PING";
    case CP_INIT: return "CP_INIT";
    case CP_KEY_READY: return "CP_KEY_READY";
    case CP_C_RECEIVED: return "CP_C_RECEIVED/CT_DONE";
    case CP_DECAP_DONE: return "CP_DECAP_DONE";
    case CP_ALL_DONE: return "CP_ALL_DONE";
    case CP_ERROR: return "CP_ERROR";
    default: return "CP_UNKNOWN";
    }
}

static void set_cp_value(uint8_t new_value, bool notify)
{
    uint8_t old_value = cp;

    cp = new_value;
    LOG("CP transition: 0x%02x (%s) -> 0x%02x (%s)%s",
        old_value, cp_name(old_value), new_value, cp_name(new_value),
        notify ? " + notify" : "");

    if (notify) {
        (void)ble_service_notify_cp(new_value);
    }
}

void pqke_state_set_cp(uint8_t new_value)
{
    LOG("CP command/event queued: 0x%02x (%s)", new_value, cp_name(new_value));
    cp = new_value;
    k_sem_give(&cp_sem);
}

uint8_t pqke_state_get_cp(void)
{
    return cp;
}

void pqke_state_reset_to_idle_no_notify(void)
{
    set_cp_value(CP_IDLE, false);
}

void pqke_opcode_thread(void)
{
    LOG("opcode thread started");

    while (1) {
        k_sem_take(&cp_sem, K_FOREVER);

        uint8_t event = cp;
        LOG("handling CP event: 0x%02x (%s)", event, cp_name(event));

        switch (event) {
        case CP_IDLE:
            LOG("idle event ignored");
            break;

        case CP_PING: {
            uint8_t resp = 0xff;
            LOG("ping received; sending 0xff response");
            (void)ble_service_notify_cp(resp);
            set_cp_value(CP_IDLE, false);
            break;
        }

        case CP_INIT: {
            LOG("key generation start: MLKEM_SEC_LEVEL=%u", MLKEM_SEC_LEVEL);
            uint32_t t0 = (uint32_t)k_uptime_get();
            int ret = pqke_crypto_generate_keypair();
            uint32_t t1 = (uint32_t)k_uptime_get();

            LOG("key generation finished: ret=%d duration=%u ms", ret, t1 - t0);
            if (ret != 0) {
                set_cp_value(CP_ERROR, true);
                break;
            }

            set_cp_value(CP_KEY_READY, true);

            LOG("public key indication start");
            t0 = (uint32_t)k_uptime_get();
            ret = pqke_transfer_deliver_public_key();
            t1 = (uint32_t)k_uptime_get();
            LOG("public key indication finished: ret=%d duration=%u ms", ret, t1 - t0);

            if (ret != 0) {
                set_cp_value(CP_ERROR, true);
                break;
            }

            /* Keep CP readable as KEY_READY until CT_DONE/CP_C_RECEIVED arrives. */
            break;
        }

        case CP_KEY_READY:
            LOG("CP_KEY_READY command received directly; re-sending status notification");
            set_cp_value(CP_KEY_READY, true);
            break;

        case CP_C_RECEIVED: {
            LOG("CT_DONE received; decapsulation start");
            uint32_t t0 = (uint32_t)k_uptime_get();
            int ret = pqke_crypto_decapsulate(pqke_crypto_ciphertext_buffer());
            uint32_t t1 = (uint32_t)k_uptime_get();
            LOG("decapsulation finished: ret=%d duration=%u ms", ret, t1 - t0);

            if (ret != 0) {
                set_cp_value(CP_ERROR, true);
                break;
            }

            set_cp_value(CP_DECAP_DONE, true);
            break;
        }

        case CP_DECAP_DONE:
            LOG("CP_DECAP_DONE command received directly; re-sending status notification");
            set_cp_value(CP_DECAP_DONE, true);
            break;

        case CP_ALL_DONE:
            LOG("session complete command received; disconnecting");
            (void)ble_service_disconnect();
            set_cp_value(CP_IDLE, false);
            break;

        default:
            LOG("unknown control opcode: 0x%02x", event);
            set_cp_value(CP_ERROR, true);
            break;
        }
    }
}

K_THREAD_DEFINE(pqke_opcode_thread_id,
                PQKE_OPCODE_THREAD_STACK_SIZE,
                pqke_opcode_thread,
                NULL, NULL, NULL,
                PQKE_OPCODE_THREAD_PRIORITY,
                0,
                0);
