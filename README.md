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

## Warning

This is a **research prototype**.

It must not be used for encryption of sensitive or real user data

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

---

## Citation

If you use this work, please cite:

@misc{BLEConnectionPQKE,
author = {Liu, Tao and Ramachandran, Gowri and Jurdak, Raja},
title = {BLE Connection-Based Post-Quantum Key Exchange (PQKE)},
year = {2026},
howpublished = {\url{https://github.com/EsperLiu/BLE_Connection_PQKE}},
note = {Supporting implementation of ML-KEM-based post-quantum key exchange over Bluetooth Low Energy. Used for the experimental evaluation in the SenSys 2026 paper: ``On the Energy Cost of Post-Quantum Key Establishment in Wireless Low-Power Personal Area Networks''.}
}

or the main energy study paper: 

@inproceedings{10.1145/3774906.3802784,
author = {Liu, Tao and Ramachandran, Gowri and Jurdak, Raja},
title = {On the Energy Cost of Post-Quantum Key Establishment in Wireless Low-Power Personal Area Networks},
year = {2026},
booktitle = {Proceedings of the 2026 ACM/IEEE International Conference on Embedded Artificial Intelligence and Sensing Systems},
series = {SenSys '26},
pages = {1137--1143},
location = {Saint Malo, France},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
doi = {10.1145/3774906.3802784},
url = {https://doi.org/10.1145/3774906.3802784},
keywords = {Post-Quantum Cryptography, Internet of Things, Personal Area Networks, Energy Estimation, Bluetooth Low Energy}
}
