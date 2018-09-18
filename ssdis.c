#include "ssdis.h"

typedef struct ss_handle{
	csh cs_handle; // Opaque handle for Capstone
	uint8_t* disasm_map; // Pointer to array tracking offsets disassembled
	uint8_t* curr_offset; // Starting offset for current linear disassembly
	uint8_t curr_size; // Current size of bytes based on starting offset
} ss_handle;

void ss_open(cs_arch arch, cs_mode mode, csh* handle){
	csh cs_handle;
	cs_open(arch, mode, &cs_handle);
	ss_handle* h = malloc(sizeof(ss_handle));
	*handle = (uintptr_t)h;
	h->cs_handle = cs_handle;
	/* Start data uninitialized until we get the code */
	h->disasm_map = 0;
	h->curr_offset = 0;
	h->curr_size = 0;
}

bool ss_disasm_iter(csh handle, const uint8_t **code, size_t* code_size,
		uint64_t* address, cs_insn* insn){
	ss_handle* h = (ss_handle*)handle;
	if( cs_disasm_iter(h->cs_handle, code, code_size, address, insn) ){
		return true;
	}
	return false;
}  

void ss_close(csh* handle){
	ss_handle* h = (ss_handle*)(*handle);
	cs_close(&(h->cs_handle));
	if( h->disasm_map ){
		free(h->disasm_map);
	}
	free(h);
}
