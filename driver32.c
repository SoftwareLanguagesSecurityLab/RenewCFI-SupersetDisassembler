#include "ssdis.h"

int main(int argc, char** argv){
	csh handle;
	ss_open(CS_ARCH_X86, CS_MODE_32, &handle);

	cs_insn *insn = cs_malloc(handle);
	
	uint8_t *code = "\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\xe9\x85\x04\x08\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\xdf\x85\x04\x08\xc3\x90";
	size_t code_size = 36;	// size of @code buffer above
	uint64_t address = 0x80485d0;	// address of first instruction to be disassembled

	// disassemble one instruction a time & store the result into @insn variable above
    	while(ss_disasm_iter(handle, (const uint8_t**)&code, &code_size, &address, insn)) {
        	// analyze disassembled instruction in @insn variable ...
        	// NOTE: @code, @code_size & @address variables are all updated
        	// to point to the next instruction after each iteration.
		printf("0x%llx: %s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    	}
	
	cs_free(insn, 1);
	ss_close(&handle);
}
