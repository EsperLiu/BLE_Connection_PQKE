#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/sys/printk.h>

#include "ble_service.h"

int main(void)
{
    int err = bt_enable(NULL);
    if (err) {
        printk("Bluetooth init failed (err %d)\n", err);
        return 0;
    }

    err = ble_service_init();
    if (err) {
        return 0;
    }

    return 0;
}
