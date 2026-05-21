# Connection-PQKE over BLE

A Zephyr-based Bluetooth Low Energy (BLE) peripheral for experimenting with **connection-oriented post-quantum key establishment (PQKE)** using **ML-KEM**. The firmware exposes a custom GATT service that lets a BLE central trigger ML-KEM key generation, receive the public key over GATT indications, send the ciphertext back using framed GATT writes, and complete decapsulation on the peripheral.

This project is intended for research prototyping and measurement, especially latency/energy profiling and connection-contiguity experiments on constrained BLE devices. It is **not production-ready security software**.

## What this project does

- Starts a Zephyr BLE peripheral with a custom 128-bit GATT service.
- Accepts one-byte control-point commands from a BLE central.
- Generates an ML-KEM key pair on the peripheral.
- Sends the ML-KEM public key to the central using GATT indications.
- Receives the ML-KEM ciphertext from the central using framed GATT writes.
- Decapsulates the ciphertext and derives the shared secret on the peripheral.
- Logs timing information for key generation, public-key transfer, ciphertext reception, and decapsulation.
- Includes a radio/contact-window experiment that can forcibly stop advertising and disconnect the active BLE connection after a configured active window.

## Repository layout

The expected Zephyr application structure is:

```text
.
├── CMakeLists.txt
├── include/
│   ├── ble_service.h
│   ├── debug_utils.h
│   ├── opcodes.h
│   ├── pqke_config.h
│   ├── pqke_crypto.h
│   ├── pqke_state.h
│   ├── pqke_transfer.h
│   └── mlkem512/
│       └── PQClean ML-KEM source files
├── prj.conf
└── src/
    ├── main.c
    ├── ble_service.c
    ├── debug_utils.c
    ├── pqke_crypto.c
    ├── pqke_state.c
    └── pqke_transfer.c
```

## Main modules

| File | Purpose |
|---|---|
| `src/main.c` | Enables the Zephyr Bluetooth stack and starts the BLE PQKE service. |
| `src/ble_service.c` | Defines the custom GATT service, advertising, connection handling, notification helper, MTU logging, and radio-window interruption logic. |
| `src/pqke_crypto.c` | Wraps the PQClean ML-KEM keypair and decapsulation functions and stores the public key, secret key, ciphertext, and shared secret buffers. |
| `src/pqke_state.c` | Implements the control-point state machine and the opcode-handling thread. |
| `src/pqke_transfer.c` | Handles public-key transfer by GATT indication and ciphertext reception by framed GATT writes. |
| `src/debug_utils.c` | Provides a simple byte-buffer hex dump helper for debugging. |
| `CMakeLists.txt` | Builds the Zephyr app and includes the ML-KEM source files. |

## GATT service

The firmware advertises a custom 128-bit service UUID:

```text
12345678-1234-5678-1234-56789abcdef0
```

The service contains four custom characteristics:

| Characteristic | UUID suffix | Properties | Purpose |
|---|---:|---|---|
| Control Point (`CP`) | `...de01` | Read, Write, Notify | Central writes one-byte opcodes; peripheral reports state changes. |
| Public Key Indication (`IND`) | `...de02` | Read, Indicate | Peripheral sends the ML-KEM public key in chunks using confirmed indications. |
| Ciphertext Write (`CT`) | `...de03` | Write, Extended Properties | Central writes framed ML-KEM ciphertext data. Reliable/prepare-write support is declared for compatibility. |
| PQ Security Level (`PQLVL`) | `...de04` | Read | Central reads the selected ML-KEM security level. |

The UUIDs are fixed placeholders for experimentation. Replace them with project-specific UUIDs if this firmware is reused outside the lab.

## Control-point protocol

The control point is a one-byte state/command interface. The numeric opcode values are defined in `include/opcodes.h`; this README uses the symbolic names.

| Symbol | Direction | Meaning |
|---|---|---|
| `CP_IDLE` | Peripheral state | Idle/default state. |
| `CP_PING` | Central → peripheral | Test command. Peripheral replies with `0xff` by notification. |
| `CP_INIT` | Central → peripheral | Start ML-KEM key generation and public-key transfer. |
| `CP_KEY_READY` | Peripheral → central | Public key has been generated and transfer is starting/available. |
| `CP_C_RECEIVED` | Internal/peripheral event | Ciphertext reception has completed; decapsulation should start. |
| `CP_DECAP_DONE` | Peripheral → central | Decapsulation completed successfully. |
| `CP_ALL_DONE` | Central → peripheral | Session is complete; peripheral disconnects and returns to idle. |
| `CP_ERROR` | Peripheral → central | Error during key generation, transfer, decapsulation, or unknown opcode handling. |

## Protocol flow

A typical exchange is:

1. The central scans for the custom service UUID.
2. The central connects to the peripheral.
3. The central discovers the four GATT characteristics.
4. The central enables notifications on `CP` and indications on `IND`.
5. The central reads `PQLVL` to confirm the configured ML-KEM level.
6. The central writes `CP_INIT` to the control point.
7. The peripheral generates an ML-KEM key pair.
8. The peripheral notifies `CP_KEY_READY`.
9. The peripheral sends the public key over `IND` in chunks of up to `PQKE_MAX_CHRC_BYTE` bytes.
10. The central reconstructs the full public key and performs ML-KEM encapsulation.
11. The central sends the ciphertext back through the `CT` characteristic using the expected frame format.
12. After the final ciphertext frame is received, the peripheral queues `CP_C_RECEIVED` internally.
13. The peripheral decapsulates the ciphertext and derives the shared secret.
14. The peripheral notifies `CP_DECAP_DONE`.
15. The central writes `CP_ALL_DONE`.
16. The peripheral disconnects and resets the control point to idle.

## Ciphertext frame format

The ciphertext receive path currently uses a compatibility framing mode:

```text
+------------------------------+----------------+
| ciphertext payload fragment  | frame number   |
+------------------------------+----------------+
| PQKE_CT_FRAME_LEN - 1 bytes  | 1 byte         |
```

The frame number is used to place the payload fragment into the correct offset of the full ML-KEM ciphertext buffer. The last frame triggers `CP_C_RECEIVED`, which starts decapsulation.

Keep the central/client implementation consistent with these constants from `include/pqke_config.h`:

- `PQKE_CT_BYTES`
- `PQKE_CT_FRAMES`
- `PQKE_CT_FRAME_LEN`
- `PQKE_MAX_CHRC_BYTE`

The current receive code also contains a legacy boundary-detection heuristic based on `offset + len + 64 >= PQKE_CT_FRAME_LEN`. If you redesign the client protocol, replace this with explicit frame headers or length fields.

## ML-KEM configuration

The selected ML-KEM level is controlled by `MLKEM_SEC_LEVEL` in `include/pqke_config.h`.

Expected values:

| `MLKEM_SEC_LEVEL` | ML-KEM variant |
|---:|---|
| `1` | ML-KEM-512 |
| `3` | ML-KEM-768 |
| `5` | ML-KEM-1024 |

`src/pqke_crypto.c` maps `MLKEM_SEC_LEVEL` to the corresponding PQClean function names. The current `CMakeLists.txt` includes `include/mlkem512` and glob-builds only `include/mlkem512/*.c`. If you switch to ML-KEM-768 or ML-KEM-1024, also update the include directory and source glob to point to the matching PQClean implementation.

## Radio-window experiment

`src/ble_service.c` includes a simple radio/contact intermittence experiment:

```c
#define RADIO_ACTIVE_WINDOW_MS    60000
#define RADIO_INACTIVE_WINDOW_MS  0
```

During an active window, the peripheral advertises and accepts a connection. At the end of the active window, advertising is stopped and any active connection is forcibly disconnected. RAM is preserved, but the CPQKE session state is reset because this connection-based protocol is treated as atomic and connection-bound.

This is useful for testing how much contiguous BLE contact time is required for a complete connection-based PQKE exchange. For normal always-on testing, keep the active window large and the inactive window at zero, or remove the window scheduling logic.

## Build requirements

You need:

- Zephyr RTOS workspace with `west` configured.
- Zephyr SDK/toolchain.
- A BLE-capable board, for example a Nordic nRF52840 development board.
- PQClean ML-KEM source files placed under the expected `include/mlkem512/` directory, or an adjusted CMake configuration for another ML-KEM level.
- The project headers under `include/`.
- A suitable `prj.conf` enabling BLE peripheral support and enough buffers/MTU for large GATT transfers.

## Example Zephyr configuration

A minimal `prj.conf` will depend on your board and exact MTU/Data Length Extension settings. The following is a starting point, not a guaranteed drop-in configuration:

```ini
CONFIG_BT=y
CONFIG_BT_PERIPHERAL=y
CONFIG_BT_DEVICE_NAME="CPQKE"
CONFIG_BT_DEVICE_APPEARANCE=0

# GATT / ATT support
CONFIG_BT_GATT_DYNAMIC_DB=n
CONFIG_BT_ATT_PREPARE_COUNT=8

# Settings are loaded if CONFIG_SETTINGS is enabled in the firmware path.
CONFIG_SETTINGS=y
CONFIG_BT_SETTINGS=y
CONFIG_FLASH=y
CONFIG_FLASH_PAGE_LAYOUT=y
CONFIG_NVS=y

# Larger buffers are usually needed for high-throughput GATT experiments.
# Tune these together with your board, controller, ATT MTU, and DLE settings.
CONFIG_BT_L2CAP_TX_MTU=498
CONFIG_BT_BUF_ACL_TX_SIZE=502
CONFIG_BT_BUF_ACL_RX_SIZE=502
CONFIG_BT_BUF_ACL_TX_COUNT=10
CONFIG_BT_BUF_ACL_RX_COUNT=10

# Optional controller-side Data Length Extension support, depending on board/controller.
CONFIG_BT_CTLR_DATA_LENGTH=y
CONFIG_BT_USER_DATA_LEN_UPDATE=y

# Logging/debug output
CONFIG_PRINTK=y
CONFIG_LOG=n
```

For small-memory boards, reduce the buffer sizes if the build fails or RAM usage is too high. For performance measurements, record the final `prj.conf`, ATT MTU, LL data length, connection interval, PHY, supply voltage, and board revision.

## Building and flashing

From the Zephyr application directory:

```bash
west build -b nrf52840dk_nrf52840 -p always .
west flash
```

Replace `nrf52840dk_nrf52840` with your target board name.

To inspect or change Zephyr options interactively:

```bash
west build -t menuconfig
```

To monitor serial output, use your preferred serial terminal or the board vendor's tooling. The firmware prints tagged logs such as `[BLE]`, `[STATE]`, `[CRYPTO]`, and `[XFER]`.

## Client-side requirements

The central/client is not included in this firmware repository. A compatible client must:

1. Connect to the advertised custom service.
2. Enable `CP` notifications.
3. Enable `IND` indications and confirm each indication.
4. Write `CP_INIT` to start the exchange.
5. Collect public-key indication chunks until the full ML-KEM public key length is reached.
6. Encapsulate using the same ML-KEM level.
7. Send the ciphertext through the `CT` characteristic using the configured frame size and frame-number byte.
8. Wait for `CP_DECAP_DONE`.
9. Write `CP_ALL_DONE` to end the session.

## Debug output

The firmware logs major events with uptime timestamps:

- BLE advertising, connection, disconnection, MTU updates, and notifications.
- Control-point state transitions.
- ML-KEM keypair and decapsulation durations.
- Public-key indication chunk submission and confirmation.
- Ciphertext frame reception and final decapsulation trigger.

The current debug path prints the derived shared secret in hex. Remove this before using the code outside controlled experiments.

## Troubleshooting

### The device does not advertise

Check that `CONFIG_BT=y`, `CONFIG_BT_PERIPHERAL=y`, and `CONFIG_BT_DEVICE_NAME` are set. Also verify that `bt_enable()` succeeds and that `ble_service_init()` is called.

### The central finds the device but not the service

Confirm that the central is scanning for the service UUID:

```text
12345678-1234-5678-1234-56789abcdef0
```

Also check whether the central is reading advertising data and scan-response data correctly.

### Public-key transfer stalls

Make sure the central enables indications on the `IND` characteristic and confirms each indication. The firmware waits for indication confirmation before submitting the next chunk.

### Ciphertext reception completes but decapsulation fails

Check that:

- The client and peripheral use the same ML-KEM level.
- The ciphertext length matches `PQKE_CT_BYTES`.
- The frame size and frame-number byte match `PQKE_CT_FRAME_LEN`.
- Frames are numbered from `0` to `PQKE_CT_FRAMES - 1`.
- The final frame is actually sent and detected by the peripheral.

### ML-KEM-768 or ML-KEM-1024 does not build

Update `CMakeLists.txt` to include the correct PQClean source directory. The uploaded CMake file currently points to `include/mlkem512` only.

### MTU remains small

The central must request a larger ATT MTU, and the peripheral must have suitable Zephyr buffer sizes. Check the firmware log line printed by the MTU update callback.

## Security notes

This project is experimental. In its current form:

- It does not authenticate the peer.
- It does not protect against man-in-the-middle attacks.
- It does not bind the derived shared secret to an application protocol transcript.
- It does not run a KDF or key confirmation step after decapsulation.
- It prints the shared secret to serial output.
- It uses placeholder UUIDs.
- It is not hardened against side-channel attacks.
- It does not automatically install the shared secret into the BLE link-layer security procedure.

Use this firmware for controlled measurements and protocol prototyping only.

## Suggested measurement practice

For repeatable experiments, record:

- Board and SoC.
- Zephyr version and SDK version.
- ML-KEM level.
- ATT MTU and LL data length.
- Connection interval, latency, and supervision timeout.
- Advertising interval.
- PHY and transmit power.
- Supply voltage.
- Power measurement tool and sampling rate.
- Whether the radio-window experiment is enabled.
- Full serial log for each run.

## License


This project is currently shared privately for academic review and research
discussion. It is not released as open-source software.

Unless otherwise agreed in writing, the code may not be redistributed,
published, sublicensed, commercialised, or reused in another project.

Third-party cryptographic implementation files, including ML-KEM/PQClean-derived
code included in the build, remain subject to their original licenses.