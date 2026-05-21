# Connection-PQKE Central / Gateway Tester

This repository contains the **central-side Zephyr test application** for the connection-oriented post-quantum key-establishment (connection-PQKE) prototype.

The application acts as the BLE **central / gateway** used to test a compatible PQKE peripheral. It scans for the custom PQKE BLE service, connects to the peripheral, receives an ML-KEM public key by GATT indication, performs ML-KEM encapsulation locally, sends the resulting ciphertext back to the peripheral, and waits for the peripheral to report successful decapsulation.

This project is intended as a **research and measurement prototype**, not as production security software.

---

## Purpose

This central application is used to drive and test the connection-oriented PQKE exchange implemented by the peripheral firmware.

At a high level, the central:

1. Actively scans for the custom PQKE service UUID.
2. Connects to a matching BLE peripheral.
3. Exchanges ATT MTU.
4. Discovers the required GATT service, characteristics, and CCC descriptor.
5. Reads the peripheral's selected PQ security level.
6. Subscribes to public-key indications.
7. Sends `CP_INIT` to start the PQKE session.
8. Receives the full ML-KEM public key.
9. Performs ML-KEM encapsulation.
10. Writes ciphertext frames to the peripheral.
11. Polls the control point until decapsulation is complete.

The expected successful end state is the log message:

```text
CONNECTION-PQKE COMPLETE
```

---

## Project Structure

```text
.
├── CMakeLists.txt
└── src
    ├── main.c
    └── mlkem512/
        ├── *.c
        └── *.h
```

Depending on the exact local layout, the ML-KEM implementation may be stored under `src/mlkem512/`, while the include path expects `mlkem512/api.h`.

The supplied `CMakeLists.txt` builds a single Zephyr application named:

```text
connection_pqke_central
```

and includes the central application source plus the ML-KEM source files.

---

## Main Components

### `src/main.c`

Contains the full BLE central test logic, including:

- active scanning;
- advertisement UUID matching;
- connection establishment;
- ATT MTU exchange;
- GATT discovery;
- public-key indication subscription;
- ML-KEM encapsulation;
- ciphertext frame writing;
- control-point polling;
- automatic rescan after disconnection.

The code is intentionally verbose in its logging so that timing and protocol behaviour can be observed during experiments.

### `src/mlkem512/`

Contains the ML-KEM implementation used by the central for encapsulation.

The current CMake configuration includes sources from:

```cmake
src/mlkem512/*.c
```

and adds the include directory:

```cmake
mlkem512
```

Check that this path matches your actual directory structure before building.

---

## BLE Protocol Overview

The central expects the peripheral to advertise the following custom 128-bit service UUID:

```text
12345678-1234-5678-1234-56789abcdef0
```

The service contains the following characteristics:

| Characteristic | UUID suffix | Direction | Purpose |
|---|---:|---|---|
| Control Point `CP` | `...de01` | central ↔ peripheral | Starts the session and reports protocol state |
| Public Key `PK` | `...de02` | peripheral → central | Sends the ML-KEM public key by indication |
| Ciphertext `CT` | `...de03` | central → peripheral | Sends ML-KEM ciphertext frames |
| PQ Level `PQLVL` | `...de04` | peripheral → central | Reports selected ML-KEM security level |

---

## Control Point Values

The central uses the following control-point opcodes:

| Name | Value | Meaning |
|---|---:|---|
| `CP_IDLE` | `0x00` | Idle state |
| `CP_PING` | `0x01` | Ping/test command |
| `CP_INIT` | `0x02` | Start a PQKE session |
| `CP_KEY_READY` | `0x03` | Peripheral has generated the key pair |
| `CP_CT_RECEIVED` | `0x04` | Peripheral has received the ciphertext |
| `CP_DECAP_DONE` | `0x05` | Peripheral has completed decapsulation |
| `CP_SESSION_DONE` | `0x06` | Session completed |
| `CP_ERROR` | `0xff` | Error state |

The central writes `CP_INIT` to begin the exchange and then polls the control point until `CP_DECAP_DONE` is observed.

---

## Supported ML-KEM Levels

The central can interpret the following `PQLVL` values:

| PQLVL | Scheme | Public key | Ciphertext | CT frame length |
|---:|---|---:|---:|---:|
| `1` | ML-KEM-512 | 800 bytes | 768 bytes | 385 bytes |
| `3` | ML-KEM-768 | 1184 bytes | 1088 bytes | 364 bytes |
| `5` | ML-KEM-1024 | 1568 bytes | 1568 bytes | 393 bytes |

The current source includes `mlkem512/api.h` directly. ML-KEM-768 and ML-KEM-1024 support are guarded by conditional compilation checks and require the corresponding implementation files and symbols to be available.

If the `PQLVL` characteristic is missing or cannot be read, the central defaults to ML-KEM-512.

---

## Ciphertext Frame Format

The central sends ciphertext to the peripheral using the original fixed-frame format expected by the peripheral:

```text
frame[0 .. N-2] = ciphertext payload
frame[N-1]      = frame number
```

where `N` is the selected `CT_FRAME_LEN`.

For ML-KEM-512, the default frame length is:

```text
CT_FRAME_LEN_512 = 385
```

This provides 384 bytes of ciphertext payload per frame, requiring two frames for the 768-byte ML-KEM-512 ciphertext.

---

## Runtime Flow

A typical successful run follows this sequence:

```text
Bluetooth initialized
Active scanning for PQKE service UUID...
PQKE service UUID matched. Connecting...
Connected
MTU exchange complete
PQKE service discovered
CP characteristic discovered
PK indication characteristic discovered
PK CCC descriptor discovered
CT write characteristic discovered
PQLVL characteristic discovered
PQLVL read
PK indication subscribed
CP_INIT written
FULL PUBLIC KEY RECEIVED
ML-KEM encapsulation start
ML-KEM encapsulation done
CT write start
CT write complete
Polling CP for decapsulation completion
CP_DECAP_DONE observed
CONNECTION-PQKE COMPLETE
```

After disconnection, the application resets its handles and state, then resumes scanning.

---

## Build Requirements

This project expects a working Zephyr development environment.

Typical requirements:

- Zephyr SDK installed.
- Zephyr workspace initialised with `west`.
- A BLE-capable board supported by Zephyr.
- A compatible PQKE peripheral running the matching service.
- ML-KEM source files available in the expected directory.

Example board targets may include Nordic nRF52-class boards, depending on your local setup.

---

## Build

From the project directory:

```bash
west build -b <board_name> .
```

For example:

```bash
west build -b nrf52840dk/nrf52840 .
```

Then flash:

```bash
west flash
```

If your Zephyr board name differs, replace `<board_name>` with the correct target for your hardware.

---

## Configuration Notes

The central uses fixed connection parameters:

```c
interval_min = 40
interval_max = 40
latency      = 0
timeout      = 400
```

BLE units:

- connection interval unit: 1.25 ms;
- supervision timeout unit: 10 ms.

So the default connection interval is:

```text
40 × 1.25 ms = 50 ms
```

and the supervision timeout is:

```text
400 × 10 ms = 4 s
```

The scan configuration uses active scanning and checks advertising data for the PQKE service UUID.

---

## Compatibility Notes

This central application is designed to work with the matching connection-PQKE peripheral firmware.

The two sides must agree on:

- service UUID;
- characteristic UUIDs;
- control-point opcode values;
- ML-KEM security level;
- public-key length;
- ciphertext length;
- ciphertext frame length;
- ciphertext frame layout;
- ATT MTU and GATT transfer behaviour.

If the central connects but the exchange does not complete, first check that the peripheral is advertising the expected service UUID and that the control-point and transfer constants match on both sides.

---

## Debugging Tips

### No device found

Check that the peripheral is advertising the expected service UUID:

```text
12345678-1234-5678-1234-56789abcdef0
```

Also check that the peripheral is connectable and currently inside any configured radio/contact window.

### Connects but discovery fails

Confirm that the peripheral exposes all required characteristics:

- CP;
- PK indication;
- CT write;
- PQLVL.

### Public key never completes

Check:

- ATT MTU negotiation;
- indication subscription;
- PK characteristic and CCC handles;
- expected public-key length;
- peripheral-side public-key transfer logic.

### Ciphertext write fails

Check:

- CT characteristic handle;
- CT frame length;
- peripheral-side expected frame format;
- write permissions;
- MTU and prepare-write settings.

### Timeout waiting for decapsulation

Check:

- ciphertext frame ordering;
- final frame number;
- peripheral-side ciphertext reconstruction;
- ML-KEM level mismatch;
- peripheral-side decapsulation logs.

---

## Research Use

This code is mainly useful for:

- testing the connection-oriented PQKE peripheral;
- measuring session completion time;
- validating public-key and ciphertext transfer behaviour;
- comparing connection-based PQKE against alternative intermittent or advertising-based designs;
- generating timing logs for experimental analysis.

The implementation prioritises observability and experiment control over software abstraction.

---

## Limitations

This prototype has several known limitations:

- It is not production-ready.
- It uses hard-coded service and characteristic UUIDs.
- It assumes a specific custom GATT protocol.
- It uses fixed ciphertext frame sizes.
- It is primarily written for controlled experiments.
- It does not implement application-layer authentication.
- It does not persist session state across disconnections.
- ML-KEM-768 and ML-KEM-1024 require matching implementation files and compile-time symbols.
- Error handling is sufficient for experimentation but not hardened for deployment.

---

## Security Notice

This code is a research prototype for evaluating post-quantum key-establishment behaviour over BLE.

Do not use it directly in production systems. A deployable system would need additional security engineering, including authentication, key confirmation, secure session binding, replay protection, lifecycle management, and careful side-channel review.

---

## License and Sharing

This project is currently shared privately for academic review and research discussion. It is not released as open-source software.

Unless otherwise agreed in writing, the code may not be redistributed, published, sublicensed, commercialised, or reused in another project.

Third-party cryptographic implementation files, including ML-KEM/PQClean-derived code included in the build, remain subject to their original licenses.
