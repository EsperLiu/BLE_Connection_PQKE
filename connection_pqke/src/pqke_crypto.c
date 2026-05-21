#include "pqke_crypto.h"
#include "debug_utils.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#define LOG(fmt, ...) \
    printk("[%8u ms] [CRYPTO] " fmt "\n", (uint32_t)k_uptime_get(), ##__VA_ARGS__)

#if MLKEM_SEC_LEVEL == 1
#define mlkem_keypair PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
#define mlkem_dec     PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
#elif MLKEM_SEC_LEVEL == 3
#define mlkem_keypair PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair
#define mlkem_dec     PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec
#elif MLKEM_SEC_LEVEL == 5
#define mlkem_keypair PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair
#define mlkem_dec     PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec
#endif

static uint8_t pk[PQKE_PK_BYTES];
static uint8_t sk[PQKE_SK_BYTES];
static uint8_t ct[PQKE_CT_BYTES];
static uint8_t ss[PQKE_SS_BYTES];

int pqke_crypto_generate_keypair(void)
{
    LOG("ML-KEM keypair start: level=%u pk=%u sk=%u ct=%u ss=%u",
        MLKEM_SEC_LEVEL, (unsigned int)sizeof(pk), (unsigned int)sizeof(sk),
        (unsigned int)sizeof(ct), (unsigned int)sizeof(ss));

    uint32_t t0 = (uint32_t)k_uptime_get();
    int ret = mlkem_keypair(pk, sk);
    uint32_t t1 = (uint32_t)k_uptime_get();

    LOG("ML-KEM keypair done: ret=%d duration=%u ms", ret, t1 - t0);
    return ret;
}

int pqke_crypto_decapsulate(const uint8_t *ciphertext)
{
    LOG("ML-KEM decapsulation start: ct_len=%u", (unsigned int)sizeof(ct));

    uint32_t t0 = (uint32_t)k_uptime_get();
    int ret = mlkem_dec(ss, ciphertext, sk);
    uint32_t t1 = (uint32_t)k_uptime_get();

    if (ret != 0) {
        LOG("ML-KEM decapsulation failed: ret=%d duration=%u ms", ret, t1 - t0);
        return ret;
    }

    LOG("ML-KEM decapsulation done: duration=%u ms", t1 - t0);
    printk("[%8u ms] [CRYPTO] Shared Secret: ", (uint32_t)k_uptime_get());
    debug_print_bytes(ss, sizeof(ss));
    return 0;
}

const uint8_t *pqke_crypto_public_key(void)
{
    return pk;
}

size_t pqke_crypto_public_key_len(void)
{
    return sizeof(pk);
}

uint8_t *pqke_crypto_ciphertext_buffer(void)
{
    return ct;
}

size_t pqke_crypto_ciphertext_len(void)
{
    return sizeof(ct);
}

const uint8_t *pqke_crypto_shared_secret(void)
{
    return ss;
}

size_t pqke_crypto_shared_secret_len(void)
{
    return sizeof(ss);
}
