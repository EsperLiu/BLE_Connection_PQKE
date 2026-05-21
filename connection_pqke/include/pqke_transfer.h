#ifndef PQKE_TRANSFER_H
#define PQKE_TRANSFER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int pqke_transfer_deliver_public_key(void);
ssize_t pqke_transfer_write_ciphertext_frame(const void *buf, uint16_t len, uint16_t offset, uint8_t flags);

#endif /* PQKE_TRANSFER_H */
