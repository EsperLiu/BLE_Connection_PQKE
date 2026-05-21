#ifndef PQKE_CRYPTO_H
#define PQKE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "pqke_config.h"

#if MLKEM_SEC_LEVEL == 1
#include "mlkem512/api.h"
#define PQKE_CT_FRAMES 2
#define PQKE_CT_FRAME_LEN 385
#define PQKE_CT_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQKE_PK_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQKE_SK_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#elif MLKEM_SEC_LEVEL == 3
#include "mlkem768/api.h"
#define PQKE_CT_FRAMES 3
#define PQKE_CT_FRAME_LEN 364
#define PQKE_CT_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQKE_PK_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQKE_SK_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#elif MLKEM_SEC_LEVEL == 5
#include "mlkem1024/api.h"
#define PQKE_CT_FRAMES 4
#define PQKE_CT_FRAME_LEN 393
#define PQKE_CT_BYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQKE_PK_BYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQKE_SK_BYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
#else
#error "Unsupported MLKEM_SEC_LEVEL. Use 1, 3, or 5."
#endif

#define PQKE_SS_BYTES 32

int pqke_crypto_generate_keypair(void);
int pqke_crypto_decapsulate(const uint8_t *ciphertext);

const uint8_t *pqke_crypto_public_key(void);
size_t pqke_crypto_public_key_len(void);

uint8_t *pqke_crypto_ciphertext_buffer(void);
size_t pqke_crypto_ciphertext_len(void);

const uint8_t *pqke_crypto_shared_secret(void);
size_t pqke_crypto_shared_secret_len(void);

#endif /* PQKE_CRYPTO_H */
