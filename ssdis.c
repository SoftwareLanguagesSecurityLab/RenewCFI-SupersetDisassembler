#include "ssdis.h"


/* Template bytes for direct unconditional jump instruction.
   The instruction jumps to itself. */
const uint8_t* jmp_template = "\xe9\xfb\xff\xff\xff";
size_t jmp_template_size = 5;
/* Template bytes for halt instruction.  Used after the last instruction, or
   to terminate sequences that end in invalid instructions. */
const uint8_t* hlt_template = "\xf4";
size_t hlt_template_size = 1;

void populate_insn(ss_handle* handle, ss_insn* insn){
	insn->id = ud_insn_mnemonic(&(handle->dis_handle)); 
	insn->address = ud_insn_off(&(handle->dis_handle));
	insn->size = ud_insn_len(&(handle->dis_handle));
	insn->insn_str = ud_insn_asm(&(handle->dis_handle));
}

void ss_open(ss_mode mode, ss_handle* handle,
		uint8_t* code, size_t code_size, uint64_t address){
	ud_init(&(handle->dis_handle));
	ud_set_mode(&(handle->dis_handle), mode);
	ud_set_syntax(&(handle->dis_handle), UD_SYN_INTEL);
	/* Initialize state with initial code buffer */
	handle->valid_seq = false;
	handle->orig_size = code_size;
	handle->orig_addr = address;
	handle->curr_offset = code;
	handle->curr_size = code_size;
	handle->curr_addr = address;
	handle->map_offset = 0;
	//Allocate as many bytes as the size of the original code
	page_calloc(&(handle->map_mem), handle->orig_size);
	handle->disasm_map = handle->map_mem.address;

	ud_set_pc(&(handle->dis_handle), address);
	ud_set_input_buffer(&(handle->dis_handle), code, code_size);
}

uint8_t ss_disassemble(ss_handle* handle, ss_insn* insn){
	ss_handle* h = handle;
	// Check that the instruction has not been visited and is valid
	if( !h->disasm_map[h->map_offset] && ud_disassemble(&(h->dis_handle)) ){
		h->disasm_map[h->map_offset] = 1;
		h->valid_seq = true;
		populate_insn(handle,insn);
		h->map_offset = (insn->address + insn->size) - h->orig_addr;
		return SS_SUCCESS;
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
			if( h->disasm_map[h->map_offset] ){
				// Return a jmp jumping to itself, since
				// the target address is at its own address.
				// We must copy the template and its size since
				// cs_disasm_iter has the side-effect of
				// changing the input pointers.
				ud_set_input_buffer(&(h->dis_handle),
					jmp_template, jmp_template_size); 
				ud_disassemble(&(h->dis_handle));
			}else{
				// If we get here, we encountered an invalid
				// instruction.  Therefore, insert a hlt to
				// ensure safe execution.
				ud_set_input_buffer(&(h->dis_handle),
					hlt_template, hlt_template_size); 
				ud_disassemble(&(h->dis_handle));
			}
			populate_insn(handle,insn);
			// Prepare to start disassembly from the next
			// starting offset.
			// If the next offset has been visited, we will find
			// out the next time this function is called.
			h->curr_offset++;
			h->curr_size--;
			h->curr_addr++;
			ud_set_input_buffer(&(h->dis_handle),
				h->curr_offset, h->curr_size);
			ud_set_pc(&(h->dis_handle), h->curr_addr); 
			h->map_offset = h->curr_addr - h->orig_addr;
			return SS_SPECIAL;
		}else{
			// If this instruction was not preceded by a valid
			// sequence, then we should skip forward, because we
			// don't want duplicate hlt or jmp instructions.
			// Loop until a valid instruction at an address we have
			// not encountered yet is reached or we hit the end
			do{
				if( h->curr_size <= 1 ) return SS_END;
				h->curr_offset++;
				h->curr_size--;
				h->curr_addr++;
				ud_set_input_buffer(&(h->dis_handle),
					h->curr_offset, h->curr_size);
				ud_set_pc(&(h->dis_handle), h->curr_addr); 
				h->map_offset = h->curr_addr - h->orig_addr;
			}while( h->disasm_map[h->map_offset] ||
				!ud_disassemble(&(h->dis_handle)) );
			h->disasm_map[h->map_offset] = 1;
			h->valid_seq = true;
			populate_insn(handle,insn);
			h->map_offset =
				(insn->address + insn->size) - h->orig_addr;
			return SS_SUCCESS;
		}
	}else{
		return SS_END;
	}
}  

void ss_close(ss_handle* handle){
	if( handle->disasm_map ){
		page_free(&handle->map_mem);
	}
}
