#define _CRT_SECURE_NO_WARNINGS
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include "binaryninjaapi.h"
#include "libvle/vle.h"
#include "vle_ext.h"

using namespace BinaryNinja;
using namespace std;

#define CTR_REG 3

// TODO add floating point instructions 0x11986ca
// TODO add evfsmulx and others (look at IDA)

class ppcVleArchitectureExtension : public ArchitectureHook
{
  public:
	ppcVleArchitectureExtension(Architecture* ppc) : ArchitectureHook(ppc) {}
    
    virtual size_t GetInstructionAlignment() const override {
        return 2;
    }

    uint32_t get_r_reg(uint32_t value){
        return value + 87;
    }

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
        vle_t* instr;
        bool should_update_flags = false;
        bool indirect = false;
        BNLowLevelILLabel *label = NULL;
        BNLowLevelILLabel *true_label = NULL;
        BNLowLevelILLabel *false_label = NULL;
        LowLevelILLabel true_tag;
        LowLevelILLabel false_tag;
        ExprId condition;
        char instr_name[50];
        
        // TODO MarkLabel https://api.binary.ninja/cpp/group__lowlevelil.html#a881c1dcf42a56b3b3cb68a2419dd1f19
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            strncpy(instr_name,instr->name,49);
            //LogInfo("FOR %s GOT %d || %d", instr_name,strncmp(instr_name, "se_",3) == 0, strncmp(instr_name, "e_", 2) == 0);
            if (strncmp(instr_name, "se_",3) == 0 || strncmp(instr_name, "e_", 2) == 0) {
                //LogInfo("ENTERED");
                if (instr_name[strlen(instr_name)-1] == '.') {
                    should_update_flags = true;
                    instr_name[strlen(instr_name)-1] = 0; // replace the dot with NULL byte so that we dont have to care
                }
                if (instr->op_type == OP_TYPE_SYNC) {
                    il.AddInstruction(il.Nop());
                } else if (instr->op_type == OP_TYPE_RET) {
                    il.AddInstruction(il.Return(il.Register(4,this->GetLinkRegister())));
                } else if (instr->op_type == OP_TYPE_TRAP) {
                    il.AddInstruction(il.Return(il.Unimplemented()));
                } else if (instr->op_type == OP_TYPE_JMP) {
                    label = il.GetLabelForAddress(this, instr->fields[0].value);
                    if (label) {
                        il.AddInstruction(il.Goto(*label));
                    } else {
                        il.AddInstruction(il.ConstPointer(4, instr->fields[0].value));
                    }
                } else if (instr->op_type == OP_TYPE_CALL) {
                    if (instr->fields[0].value != (uint32_t) addr + instr->size) {
                        il.AddInstruction(il.Call(il.ConstPointer(4,instr->fields[0].value)));
                    } else {
                        il.AddInstruction(il.SetRegister(4,this->GetLinkRegister(),il.ConstPointer(4,instr->fields[0].value)));
                    }
                } else if (instr->op_type == OP_TYPE_CJMP) {
                    /*
                    if (instr->fields[0].type == TYPE_JMP) {
                        result.AddBranch(TrueBranch, instr->fields[0].value);// + (uint32_t) addr) & 0xffffffff);
                        result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                    } else if (instr->fields[0].type == TYPE_CR) {
                        result.AddBranch(TrueBranch,(instr->fields[1].value));// + (uint32_t) addr) & 0xffffffff);
                        result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                    }
                    */
                    if (instr->fields[0].type == TYPE_JMP) {
                        // True branch
                        true_label = il.GetLabelForAddress(this, instr->fields[0].value);
                        if (!true_label) {
                            il.MarkLabel(true_tag);
                            il.AddInstruction(il.Jump(il.ConstPointer(4,instr->fields[0].value)));
                        }
                    } else if (instr->fields[0].type == TYPE_CR) {
                        // True branch
                        true_label = il.GetLabelForAddress(this, instr->fields[1].value);
                        if (!true_label) {
                            il.MarkLabel(true_tag);
                            il.AddInstruction(il.Jump(il.ConstPointer(4,instr->fields[1].value)));
                        }
                    } else {
                        return false;
                    }
                    
                    // False Branch
                    false_label = il.GetLabelForAddress(this, ((uint32_t) addr + instr->size));
                    if (!false_label) {
                        il.MarkLabel(false_tag);
                    }
                    
                    switch (instr->cond) {
                        case COND_GE:
                            condition = il.FlagGroup(3);
                            break;
                        case COND_LE:
                            condition = il.FlagGroup(1);
                            break;
                        case COND_NE:
                            condition = il.FlagGroup(5);
                            break;
                        case COND_VC:
                            condition = il.Unimplemented();
                            break;
                        case COND_LT:
                            condition = il.FlagGroup(0);
                            break;
                        case COND_GT:
                            condition = il.FlagGroup(2);
                            break;
                        case COND_EQ:
                            condition = il.FlagGroup(4);
                            break;
                        case COND_VS:
                            condition = il.Unimplemented();
                            break;
                        default:
                            break;
                    }

                    if (true_label && false_label)
                        il.AddInstruction(il.If(condition,*true_label,*false_label));            
                    else if (true_label)
                        il.AddInstruction(il.If(condition,*true_label,false_tag));
                    else if (false_label)
                        il.AddInstruction(il.If(condition,true_tag,*false_label));
                    else
                        il.AddInstruction(il.If(condition,true_tag,false_tag));

                } else if (strcmp(instr_name,"se_mtctr") == 0) {
                    il.AddInstruction(il.SetRegister(4, CTR_REG, il.Register(4, this->get_r_reg(instr->fields[0].value))));
                } else if (strcmp(instr_name,"se_mfctr") == 0) {
                    il.AddInstruction(il.SetRegister(4, this->get_r_reg(instr->fields[0].value), il.Register(4, CTR_REG)));
                } else if (strcmp(instr_name,"se_mflr") == 0) {
                    il.AddInstruction(il.SetRegister(4, this->get_r_reg(instr->fields[0].value), il.Register(4, this->GetLinkRegister())));
                } else if (strcmp(instr_name,"se_mtspr") == 0) {
                    il.AddInstruction(il.SetRegister(4, CTR_REG, il.Register(4, this->get_r_reg(instr->fields[0].value))));
                } else if (strcmp(instr_name,"se_mfspr") == 0) {
                    il.AddInstruction(il.SetRegister(4, this->get_r_reg(instr->fields[0].value), il.Register(4, CTR_REG)));
                } else if (strcmp(instr_name,"se_bctr") == 0) {
                    il.AddInstruction(il.Jump(il.Register(4, CTR_REG)));
                } else if (strcmp(instr_name,"se_bctrl") == 0) {
                    il.AddInstruction(il.Call(il.Register(4, CTR_REG)));
                } else if (strcmp(instr_name,"e_lis") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ShiftLeft(
                                4,
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                ),
                                il.Const(
                                    4,
                                    16
                                )
                            )
                        )
                    );
                    LogInfo("%s AT 0x%x", instr_name, (uint32_t)addr);
                } else if (false) {
                
                } else if (false) {
                    
                } else if (false) {

                } else if (false) {
                
                } else if (false) {
                    
                } else if (false) {

                } else if (false) {
                
                } else if (false) {
                    
                } else if (false) {

                } else if (false) {
                
                } else if (false) {
                    
                } else if (false) {

                } else if (false) {
                   
                } else {
                    //LogInfo("NOT LIFTED %s AT 0x%x", instr_name, (uint32_t)addr);
                }
                return true;
            }
        }
		return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
	}

    virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len, std::vector< InstructionTextToken > &result) override
	{
        char tmp[256] = {0};
		vle_t* instr;
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            //if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2) == 0) {
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
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            //if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2) == 0) {
                result.length = instr->size;
                uint32_t target;
                switch (instr->op_type) {
                    case OP_TYPE_JMP:
                        result.AddBranch(UnconditionalBranch,(instr->fields[0].value));// + (uint32_t) addr) & 0xffffffff);
                        break;
                    case OP_TYPE_CJMP:
                        if (instr->fields[0].type == TYPE_JMP) {
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