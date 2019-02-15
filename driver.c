#include "ssdis.h"

int main(){
	ss_handle handle;
	ss_insn insn;
	
	uint8_t *code = (uint8_t*)"\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\xe9\x85\x04\x08\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\xdf\x85\x04\x08\xc3\x90";
	size_t code_size = 36;	// size of code
	uint64_t address = 0x80485d0;	// address of first instruction to be disassembled

	ss_open(SS_MODE_32, &handle, code, code_size, address);
	// disassemble and store in insn
    	while(ss_disassemble(&handle, &insn)) {
		printf("0x%llx: %s\n", insn.address, insn.insn_str);
    	}
	
	ss_close(&handle);
	return 0;
}
