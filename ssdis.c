#include "ssdis.h"

typedef struct ss_handle{
	csh cs_handle; // Opaque handle for Capstone
	uint8_t* disasm_map; // Pointer to array tracking visited offsets
	size_t orig_size; // Size of the initial code
	uint64_t orig_addr; // Original base address
	const uint8_t* curr_offset; // Starting offset for linear disassembly
	size_t curr_size; // Current size of bytes based on starting offset
	uint64_t curr_addr; // Current address based on starting offset
	bool valid_seq; // Whether we found at least 1 new valid instruction
} ss_handle;

/* Template bytes for direct unconditional jump instruction.
   The instruction jumps to itself. */
const uint8_t* jmp_template = "\xe9\xfb\xff\xff\xff";
size_t jmp_template_size = 5;
/* Template bytes for halt instruction.  Used after the last instruction, or
   to terminate sequences that end in invalid instructions. */
const uint8_t* hlt_template = "\xf4";
size_t hlt_template_size = 1;

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
	h->valid_seq = false;
}

bool ss_disasm_iter(csh handle, const uint8_t **code, size_t* code_size,
		uint64_t* address, cs_insn* insn){
	ss_handle* h = (ss_handle*)handle;
	uint64_t map_offset;
	/* Check whether we have set cur_offset.  If not, we are starting
		a new disassembly, and need to set the start offset and size */
	if( !(h->curr_offset) ){
		h->orig_size = *code_size;
		h->orig_addr = *address;
		h->curr_offset = *code;
		h->curr_size = *code_size;
		h->curr_addr = *address;
		//Allocate as many bytes as the size of the original code
		h->disasm_map = calloc(h->orig_size,1);
	}
	map_offset = *address - h->orig_addr;
	// Check that the instruction has not been visited and is valid
	if( !h->disasm_map[map_offset] &&
	  cs_disasm_iter(h->cs_handle, code, code_size, address, insn) ){
		h->disasm_map[map_offset] = 1;
		h->valid_seq = true;
		return true;
	}else if(h->curr_size > 0){
		if( h->valid_seq ){
			// If this instruction was preceded by a valid sequence,
			// then we should return a special instruction, but
			// after returning a special instruction, the valid
			// sequence has ended.
			h->valid_seq = false;
			// If we have already encountered this offset,
			// return a jump instruction to the offset
			// and try next offset
			if( h->disasm_map[map_offset] ){
				// Return a jmp jumping to itself, since
				// the target address is at its own address.
				// We must copy the template and its size since
				// cs_disasm_iter has the side-effect of
				// changing the input pointers.
				const uint8_t* jmp_ptr = jmp_template;
				size_t jmp_sze = jmp_template_size; 
				cs_disasm_iter(h->cs_handle,
					&jmp_ptr, &jmp_sze, address, insn);	
			}else{
				// If we get here, we encountered an invalid
				// instruction.  Therefore, insert a hlt to
				// ensure safe execution.
				const uint8_t* hlt_ptr = hlt_template;
				size_t hlt_sze = hlt_template_size;
				cs_disasm_iter(h->cs_handle,
					&hlt_ptr, &hlt_sze, address, insn);	
			}
			// Loop until we encounter a new offset
			// so that we don't insert useless jmps
			//do{
				h->curr_offset++;
				h->curr_size--;
				h->curr_addr++;
			//	map_offset = h->curr_addr - h->orig_addr;
			//}while( h->disasm_map[map_offset] && h->curr_size > 1 );
			*code = h->curr_offset;
			*code_size = h->curr_size;
			*address = h->curr_addr;
			return true;
		}else{
			// If this instruction was not preceded by a valid
			// sequence, then we should skip forward, because we
			// don't want duplicate hlt or jmp instructions.
			// Loop until a valid instruction at an address we have
			// not encountered yet is reached or we hit the end
			do{
				if( h->curr_size <= 1 ) return false;
				h->curr_offset++;
				h->curr_size--;
				h->curr_addr++;
				*code = h->curr_offset;
				*code_size = h->curr_size;
				*address = h->curr_addr;
				map_offset = h->curr_addr - h->orig_addr;
			}while( h->disasm_map[map_offset] ||
				!cs_disasm_iter(h->cs_handle,
					code, code_size, address, insn));
			h->disasm_map[map_offset] = 1;
			h->valid_seq = true;
			return true;
		}
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
