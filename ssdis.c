#include "ssdis.h"

void ss_open(cs_arch arch, cs_mode mode, csh* handle){
	cs_open(arch, mode, handle);	
}

bool ss_disasm_iter(csh handle, const uint8_t **code, size_t* code_size, uint64_t* address, cs_insn* insn){
	if( cs_disasm_iter(handle, code, code_size, address, insn) ){
		return true;
	}
	return false;
}  

void ss_close(csh* handle){
	cs_close(handle);
}
