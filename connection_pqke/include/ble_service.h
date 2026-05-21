#ifndef BLE_SERVICE_H
#define BLE_SERVICE_H

#include <stdint.h>

#include <zephyr/bluetooth/gatt.h>

int ble_service_init(void);
int ble_service_notify_cp(uint8_t value);
int ble_service_disconnect(void);
const struct bt_gatt_attr *ble_service_public_key_indicate_attr(void);

#endif /* BLE_SERVICE_H */
