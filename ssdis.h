#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include <capstone/capstone.h>

#define SS_END 0
#define SS_SUCCESS 1
#define SS_SPECIAL 2

void ss_open(cs_arch arch, cs_mode mode, csh* handle);

uint8_t ss_disasm_iter(csh handle, const uint8_t **code, size_t* code_size, uint64_t* address, cs_insn* insn);

void ss_close(csh* handle);
