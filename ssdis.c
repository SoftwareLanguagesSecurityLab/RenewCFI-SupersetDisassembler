#include "ssdis.h"

typedef struct ss_handle{
	csh cs_handle; // Opaque handle for Capstone
	uint8_t* disasm_map; // Pointer to array tracking visited offsets
	size_t orig_size; // Size of the initial code
	const uint8_t* curr_offset; // Starting offset for linear disassembly
	size_t curr_size; // Current size of bytes based on starting offset
	uint64_t curr_addr; // Current address based on starting offset
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
	h->orig_size = 0;
	h->curr_addr = 0;
}

bool ss_disasm_iter(csh handle, const uint8_t **code, size_t* code_size,
		uint64_t* address, cs_insn* insn){
	ss_handle* h = (ss_handle*)handle;
	/* Check whether we have set cur_offset.  If not, we are starting
		a new disassembly, and need to set the start offset and size */
	if( !(h->curr_offset) ){
		h->orig_size = *code_size;
		h->curr_offset = *code;
		h->curr_size = *code_size;
		h->curr_addr = *address;
		//Allocate as many bytes as the size of the original code
		h->disasm_map = malloc(h->orig_size);
	}
	if( cs_disasm_iter(h->cs_handle, code, code_size, address, insn) ){
		return true;
	}else if(h->curr_size > 1){
		// Loop until a valid instruction is reached or we hit the end
		do{
			if( h->curr_size <= 1 ) return false;
			h->curr_offset++;
			h->curr_size--;
			h->curr_addr++;
			*code = h->curr_offset;
			*code_size = h->curr_size;
			*address = h->curr_addr;
		}while(!cs_disasm_iter(h->cs_handle, code, code_size, address, insn));
		return true;
	}else{
		return false;
	}
}  

void ss_close(csh* handle){
	ss_handle* h = (ss_handle*)(*handle);
	cs_close(&(h->cs_handle));
	if( h->disasm_map ){
		free(h->disasm_map);
	}
	free(h);
}
