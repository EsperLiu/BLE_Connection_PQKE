#ifndef OPCODES_H
#define OPCODES_H

#define CP_IDLE        0U
#define CP_PING        1U
#define CP_INIT        2U
#define CP_KEY_READY   3U
#define CP_C_RECEIVED  4U  /* Also used as explicit CT_DONE command. */
#define CP_DECAP_DONE  5U
#define CP_ALL_DONE    6U
#define CP_ERROR       255U

#endif /* OPCODES_H */
