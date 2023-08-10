#include "ssdis.h"

int main(){
	ss_handle handle;
	ss_insn insn;

	uint8_t *code = (uint8_t*)"\x48\x89\xf8\x48\x83\xf8\x00\x74\x19\x48\xb8\x4e\x07\x40\x00\x00\x00\x00\x00\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\x48\xb8\x44\x07\x40\x00\x00\x00\x00\x00\xc3";
	size_t code_size = 45;  // size of code
	uint64_t address = 0x400730;    // address of first instruction to be disassembled

	ss_open(SS_MODE_64, true, &handle, code, code_size, address);
	// disassemble and store in insn
    	while(ss_disassemble(&handle, &insn)) {
		printf("0x%lx: %s\n", insn.address, insn.insn_str);
    	}
	
	ss_close(&handle);
	return 0;
}
