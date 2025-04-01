#pragma once
#include "types.h"

void stop_periodic_timer(void);
void schedule_periodic_timer(uint64_t interval_ns);
void schedule_singleshot_timer(uint64_t delay_ns);
