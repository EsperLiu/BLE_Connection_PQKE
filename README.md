# BLE Connection-Based PQKE (Post-Quantum Key Exchange)

This repository implements a **connection-based Post-Quantum Key Exchange (PQKE)** protocol over **Bluetooth Low Energy (BLE)** using the **ML-KEM (Kyber)** algorithm.

The system replaces classical **ECDH-based BLE Secure Connections pairing** with a **post-quantum alternative**, while preserving BLE’s standard connection-oriented architecture.

This implementation is primarily intended for **experimental performance profiling and protocol evaluation**. It is not designed for production security use or real-world data encryption.

---

## Repository Structure

connection_pqke/
Peripheral implementation (Zephyr RTOS BLE Peripheral)

connection_pqke_central/
Central implementation (Zephyr RTOS BLE Central)

Each directory contains its own detailed technical README.

---

## Scope

This project focuses on:

- BLE connection-based PQKE protocol design
- ML-KEM integration into BLE GATT-based pairing flow
- Fragmentation and MTU-aware transport of PQC artifacts
- Empirical evaluation of computation vs communication overhead

---

## Warning

This is a **research prototype**.

It must not be used for:
- production security systems
- encryption of sensitive or real user data
- deployment in safety-critical environments

Cryptographic correctness is assumed at the algorithm level (ML-KEM), but system-level security hardening (authentication, replay protection, secure bootstrapping) is not fully implemented.

---

## Hardware / Platform Support

Validated on:
- Nordic nRF52840 DK

Compatible with:
- Any BLE-capable board supported by **Zephyr RTOS**
- Devices supporting GATT + ATT MTU negotiation

---

## Research Context

This implementation is designed for studying:

- Post-quantum migration of BLE pairing mechanisms
- Energy and latency overhead of ML-KEM in constrained IoT devices
- Impact of BLE MTU / L2CAP fragmentation on PQKE performance
- Communication vs computation trade-offs in embedded PQC systems


