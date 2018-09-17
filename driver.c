#include "ssdis.h"

int main(int argc, char** argv){
	csh handle;
	ss_open(CS_ARCH_X86, CS_MODE_64, &handle);

	cs_insn *insn = cs_malloc(handle);
	
	uint8_t *code = "\x90\x91\x92";
	size_t code_size = 3;	// size of @code buffer above
	uint64_t address = 0x1000;	// address of first instruction to be disassembled

	// disassemble one instruction a time & store the result into @insn variable above
    	while(ss_disasm_iter(handle, (const uint8_t**)&code, &code_size, &address, insn)) {
        	// analyze disassembled instruction in @insn variable ...
        	// NOTE: @code, @code_size & @address variables are all updated
        	// to point to the next instruction after each iteration.
		printf("%s\t%s\n", insn->mnemonic, insn->op_str);
    	}
	
	cs_free(insn, 1);
	ss_close(&handle);
}
