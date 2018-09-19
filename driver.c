#include "ssdis.h"

int main(int argc, char** argv){
	csh handle;
	ss_open(CS_ARCH_X86, CS_MODE_64, &handle);

	cs_insn *insn = cs_malloc(handle);
	
	uint8_t *code = "\x48\x89\xf8\x48\x83\xf8\x00\x74\x19\x48\xb8\x4e\x07\x40\x00\x00\x00\x00\x00\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\x48\xb8\x44\x07\x40\x00\x00\x00\x00\x00\xc3";
	size_t code_size = 45;	// size of @code buffer above
	uint64_t address = 0x400730;	// address of first instruction to be disassembled

	// disassemble one instruction a time & store the result into @insn variable above
    	while(ss_disasm_iter(handle, (const uint8_t**)&code, &code_size, &address, insn)) {
        	// analyze disassembled instruction in @insn variable ...
        	// NOTE: @code, @code_size & @address variables are all updated
        	// to point to the next instruction after each iteration.
		printf("0x%lx: %s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    	}
	
	cs_free(insn, 1);
	ss_close(&handle);
}
