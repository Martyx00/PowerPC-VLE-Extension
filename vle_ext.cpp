#define _CRT_SECURE_NO_WARNINGS
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include "binaryninjaapi.h"
#include "libvle/vle.h"
#include "vle_ext.h"

using namespace BinaryNinja;
using namespace std;


// This is a wrapper for the x86 architecture. Its useful for extending and improving
// the existing core x86 architecture.
class ppcVleArchitectureExtension : public ArchitectureHook
{
  public:
	ppcVleArchitectureExtension(Architecture* ppc) : ArchitectureHook(ppc) {}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
        /*char tmp[256] = {0};
		vle_t* instr;
        vle_handle handle;
        if ((instr = vle_decode_one(data, 4))) {
			vle_snprint(tmp, 256,(uint32_t) addr, instr);
            //LogInfo("GOT %s",tmp);
        }*/
        /*if (vle_init(&handle, data, 4, (uint32_t) addr)) {
            printf("failed to initialize handle\n");
            return false;
        } else {
            instr = vle_next(&handle);
            LogInfo("ACTUALLY HERE: %s",instr->name);
            if (strcmp(instr->name,"se_slwi") == 0) {
                il.AddInstruction(il.Unimplemented());
                vle_snprint(tmp, 256, instr);
                LogInfo("ACTUALLY HERE: %s",tmp);
                len = instr->size;
                return true;
            }
        }
        
		if (asmx86::Disassemble32(data, addr, len, &instr))
		{
			switch (instr.operation)
			{
			case CPUID:
				// The default implementation of CPUID doesn't set registers to constant values
				// Here we'll emulate a Intel(R) Core(TM) i5-6267U CPU @ 2.90GHz with _eax set to 1
				il.AddInstruction(il.Unimplemented());
                LogInfo("ACTUALLY_HERE");
				len = instr.size;
				return true;
			default:
				break;
			}
		}*/
		return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
	}

    virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len, std::vector< InstructionTextToken > &result) override
	{
        char tmp[256] = {0};
		vle_t* instr;
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            //if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2)) {
                len = instr->size;
                // Add instruction name
                result.emplace_back(InstructionToken, instr->name);
                result.emplace_back(TextToken, " ");
                char hex_val[20] = {0};
                char reg_str[10] = {0};
                for (int op_index = 0; op_index < instr->n; op_index++) {
                    switch(instr->fields[op_index].type) {
                        case TYPE_REG:
                            sprintf(reg_str, "r%d", instr->fields[op_index].value); 
                            result.emplace_back(RegisterToken, reg_str);
                            break;
                        case TYPE_IMM:
                            sprintf(hex_val, "0x%x", instr->fields[op_index].value); 
                            result.emplace_back(IntegerToken, hex_val, instr->fields[op_index].value);
                            break;
                        case TYPE_MEM:
                            if (op_index < (instr->n -1)){
                                sprintf(reg_str, "r%d", instr->fields[op_index].value); 
                                sprintf(hex_val, "0x%x", instr->fields[op_index+1].value); 
                                result.emplace_back(IntegerToken, hex_val, instr->fields[op_index].value);
                                result.emplace_back(OperandSeparatorToken, "(");
                                result.emplace_back(RegisterToken, reg_str);
                                result.emplace_back(OperandSeparatorToken, ")");
                            }
                            break;
                        case TYPE_JMP:
                            sprintf(hex_val, "0x%x", (instr->fields[op_index].value));// + (uint32_t) addr)); 
                            result.emplace_back(IntegerToken, hex_val, instr->fields[op_index].value);
                            break;
                        case TYPE_CR:
                            sprintf(reg_str, "cr%d", instr->fields[op_index].value); 
                            result.emplace_back(RegisterToken, reg_str);
                            break;
                        default:
                            break;
                    }
                    result.emplace_back(OperandSeparatorToken, ", ");
                }
                result.pop_back();
                /*vle_snprint(tmp, 256,(uint32_t) addr, instr);
                LogInfo("GOT %s",tmp);
                LogInfo("GOT %d", instr->op_type);*/
                return true;
            //}
			
        }
		return ArchitectureHook::GetInstructionText(data, addr, len, result);
	}

    virtual bool GetInstructionInfo(const uint8_t *data, uint64_t addr, size_t maxLen, InstructionInfo &result) override
	{
        char tmp[256] = {0};
		vle_t* instr;
        if (addr == 0x11d0bb6) {
            LogInfo("GOT TO %x", (uint32_t) addr);
        }
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            //if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2)) {
                if (addr == 0x11d0bb6) {
                    vle_snprint(tmp, 256,(uint32_t) addr, instr);
                    LogInfo("GOT %s",tmp);
                    LogInfo("GOT %d", instr->op_type);
                }
                result.length = instr->size;
                uint32_t target;
                switch (instr->op_type) {
                    case OP_TYPE_JMP:
                        result.AddBranch(UnconditionalBranch,(instr->fields[0].value));// + (uint32_t) addr) & 0xffffffff);
                        break;
                    case OP_TYPE_CJMP:
                        if (instr->fields[0].type == TYPE_JMP) {
                            if (addr == 0x011d0b66) {
                                LogInfo("GOT %s %x %d",instr->name, instr->fields[0].value, instr->n);
                            }
                            result.AddBranch(TrueBranch, instr->fields[0].value);// + (uint32_t) addr) & 0xffffffff);
                            result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                        } else if (instr->fields[0].type == TYPE_CR) {
                            result.AddBranch(TrueBranch,(instr->fields[1].value));// + (uint32_t) addr) & 0xffffffff);
                            result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                        } else {
                            return false;
                        }
                        break;
                    case OP_TYPE_CALL:
                        target = (instr->fields[0].value);// + (uint32_t) addr) & 0xffffffff;
                        if (target != ((uint32_t) addr + instr->size)) 
                            result.AddBranch(CallDestination,(instr->fields[0].value));// + (uint32_t) addr) & 0xffffffff);
                        break;
                    case OP_TYPE_RCALL:
                        result.AddBranch(IndirectBranch);
                        break;
                    case OP_TYPE_RJMP:
                        result.AddBranch(IndirectBranch);
                        break;
                    case OP_TYPE_RET:
                        result.AddBranch(FunctionReturn);
                        break;
                    case OP_TYPE_SWI:
                        result.AddBranch(SystemCall);
                        break;
                    case OP_TYPE_TRAP:
                        result.AddBranch(FunctionReturn);
                        break;
                    default:
                        break;
                }
                /*vle_snprint(tmp, 256,(uint32_t) addr, instr);
                LogInfo("GOT %s",tmp);
                LogInfo("GOT %d", instr->op_type);*/
                return true;
            //}
			
        }
		return ArchitectureHook::GetInstructionInfo(data, addr, maxLen, result);
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		// Make sure we load after the original x86 plugin loads
		AddRequiredPluginDependency("arch_ppc");
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Architecture* ppc_vle_ext = new ppcVleArchitectureExtension(Architecture::GetByName("ppc"));
		Architecture::Register(ppc_vle_ext);
		return true;
	}
}