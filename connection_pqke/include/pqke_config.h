#ifndef PQKE_CONFIG_H
#define PQKE_CONFIG_H

/* Thread configuration */
#define PQKE_OPCODE_THREAD_STACK_SIZE 40000
#define PQKE_OPCODE_THREAD_PRIORITY   7

/* Maximum public-key bytes sent in one GATT indication. */
#define PQKE_MAX_CHRC_BYTE 400

/*
 * ML-KEM security level selector:
 *   1 -> ML-KEM-512
 *   3 -> ML-KEM-768
 *   5 -> ML-KEM-1024
 */
#ifndef MLKEM_SEC_LEVEL
#define MLKEM_SEC_LEVEL 1
#endif

/* 50ms connectable advertising interval for clean DK-to-DK testing (0.625ms/unit) */
#define PQKE_ADV_INTERVAL_MIN 75
#define PQKE_ADV_INTERVAL_MAX 80

/* Optional preferred connection parameter request after connection. */
#define PQKE_CONN_INTERVAL_MIN 40      /* 50 ms */
#define PQKE_CONN_INTERVAL_MAX 40     /* 50 ms */
#define PQKE_CONN_LATENCY      0
#define PQKE_CONN_TIMEOUT      400    /* 4 s */

#endif /* PQKE_CONFIG_H */
