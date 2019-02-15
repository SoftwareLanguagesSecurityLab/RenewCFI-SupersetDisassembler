#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include <udis86.h>
#include <pagealloc.h>

typedef struct ss_insn {
	enum ud_mnemonic_code id;
	uint64_t address;
	uint16_t size;
	uint8_t* bytes;
	const char* insn_str;
} ss_insn;

#define SS_END 0
#define SS_SUCCESS 1
#define SS_SPECIAL 2

typedef uint8_t ss_mode;
#define SS_MODE_32 32
#define SS_MODE_64 64

typedef struct ss_handle{
	ud_t dis_handle; // Opaque handle for disassembler
	pa_entry_t map_mem; // Handle for allocated disasm_map memory
	uint64_t map_offset; // Current offset into the map
	uint8_t* disasm_map; // Pointer to array tracking visited offsets
	size_t orig_size; // Size of the initial code
	uint64_t orig_addr; // Original base address
	const uint8_t* curr_offset; // Starting offset for linear disassembly
	size_t curr_size; // Current size of bytes based on starting offset
	uint64_t curr_addr; // Current address based on starting offset
	bool valid_seq; // Whether we found at least 1 new valid instruction
} ss_handle;

void ss_open(ss_mode mode, ss_handle* handle, uint8_t* code, size_t code_size, uint64_t address);

uint8_t ss_disassemble(ss_handle* handle, ss_insn* insn);

void ss_close(ss_handle* handle);
