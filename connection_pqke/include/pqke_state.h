#ifndef PQKE_STATE_H
#define PQKE_STATE_H

#include <stdint.h>

void pqke_state_set_cp(uint8_t new_value);
uint8_t pqke_state_get_cp(void);
void pqke_state_reset_to_idle_no_notify(void);
void pqke_opcode_thread(void);

#endif /* PQKE_STATE_H */
