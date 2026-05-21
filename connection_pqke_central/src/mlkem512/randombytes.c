#include <stdint.h>
#include <stddef.h>
#include "randombytes.h"
#include <zephyr/random/random.h>

int randombytes(uint8_t *output, size_t n){
    sys_rand_get(output, n);
    return 0;
}