#pragma once

void gdb_stub(uint64_t* regs, uint64_t* trap_frame);
int gdb_stub_active(void);
void gdb_stub_syscall(const char* name, int nargs, uint64_t* args);
