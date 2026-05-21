#include "debug_utils.h"

#include <zephyr/sys/printk.h>

void debug_print_bytes(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printk("%02x ", buf[i]);
    }
    printk("\n");
}
