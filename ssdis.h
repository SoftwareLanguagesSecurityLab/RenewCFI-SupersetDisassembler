#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include <udis86.h>
#include <pagealloc.h>

#define RECORD_DISASM_STATS

#ifdef RECORD_DISASM_STATS
#include <time.h>

extern struct timespec disasm_timer;
extern struct timespec new_inst_timer;
extern struct timespec valid_seq_timer;
extern struct timespec invalid_seq_timer;
extern struct timespec end_seq_timer;
#endif

typedef struct ss_insn {
	enum ud_mnemonic_code id;
	uint64_t address;
	uint16_t size;
	const uint8_t* bytes;
	const char* insn_str;
} ss_insn;

#define SS_END 0
#define SS_SUCCESS 1
#define SS_SPECIAL 2

typedef uint8_t ss_mode;
#define SS_MODE_32 32
#define SS_MODE_64 64

#define SS_INS_JMP	UD_Ijmp
#define SS_INS_RET	UD_Iret
#define SS_INS_CALL	UD_Icall
#define SS_INS_JAE	UD_Ijae
#define SS_INS_JA	UD_Ija
#define SS_INS_JBE	UD_Ijbe
#define SS_INS_JB	UD_Ijb
#define SS_INS_JCXZ	UD_Ijcxz
#define SS_INS_JECXZ	UD_Ijecxz
#define SS_INS_JE	UD_Ijz		// je/jz are synonyms
#define SS_INS_JZ	UD_Ijz
#define SS_INS_JGE	UD_Ijge
#define SS_INS_JG	UD_Ijg
#define SS_INS_JLE	UD_Ijle
#define SS_INS_JL	UD_Ijl
#define SS_INS_JNE	UD_Ijnz		// jne/jnz are synonyms
#define SS_INS_JNZ	UD_Ijnz
#define SS_INS_JNO	UD_Ijno
#define SS_INS_JNP	UD_Ijnp
#define SS_INS_JNS	UD_Ijns
#define SS_INS_JO	UD_Ijo
#define SS_INS_JP	UD_Ijp
#define SS_INS_JRCXZ	UD_Ijrcxz
#define SS_INS_JS	UD_Ijs

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

void ss_open(ss_mode mode, bool gen_insn_str, ss_handle* handle, const uint8_t* code, size_t code_size, uint64_t address);

uint8_t ss_disassemble(ss_handle* handle, ss_insn* insn);

void ss_close(ss_handle* handle);
