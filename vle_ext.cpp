#define _CRT_SECURE_NO_WARNINGS
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "lowlevelilinstruction.h"
#include "libvle/vle.h"
#include "vle_ext.h"

using namespace BinaryNinja;
using namespace std;

#define CTR_REG 3
#define MSR_REG 151 // TODO dummy use of PPC_REG_VS63

#define CR0_UNSIGNED_FLAG 2
#define IL_FLAG_XER_CA 34

uint32_t cr_unsigned_array[] = {
    2, // CR0
    4, // CR1
    6, // CR2
    8, // CR3
    10, // CR4
    12, // CR5
    14, // CR6
    16 // CR7
};

enum VLEIntrinsics{
    CNTLWZ_INTRINSIC
};

// TODO add floating point instructions 0x11986ca
// TODO add evfsmulx and others (look at IDA) 0115DDD0
// TODO add Machine State Register
// TODO MTSPR decoding

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

    uint32_t get_cr_reg(uint32_t value){
	    return value + 12;
	}

    virtual std::string GetIntrinsicName (uint32_t intrinsic) override {
         switch (intrinsic)  {
            case CNTLWZ_INTRINSIC:
                return "CountLeadingZeros";
            default:
                return "";
            }
    }

    virtual std::vector<uint32_t> GetAllIntrinsics() override {
        return vector<uint32_t> {
            CNTLWZ_INTRINSIC
        };
    }

    virtual std::vector<NameAndType> GetIntrinsicInputs (uint32_t intrinsic) override {
        switch (intrinsic)
            {
                case CNTLWZ_INTRINSIC:
                    return {
                        NameAndType("WORD", Type::IntegerType(4, false))
                    };
                default:
                    return vector<NameAndType>();
            }
    }

    virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs (uint32_t intrinsic) override {
        switch (intrinsic)
            {
                case CNTLWZ_INTRINSIC:
                    return { Type::IntegerType(4, false) };
                    //return vector<Confidence<Ref<Type>>>();
                default:
                    return vector<Confidence<Ref<Type>>>();
            }
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
            len = instr->size;
            if (strncmp(instr_name, "se_",3) == 0 || strncmp(instr_name, "e_", 2) == 0) {
            //if (true) {
                //LogInfo("ENTERED");
                //len = instr->size;
                if (instr_name[strlen(instr_name)-1] == '.') {
                    should_update_flags = true;
                    instr_name[strlen(instr_name)-1] = 0; // replace the dot with NULL byte so that we dont have to care
                }
                if (instr->op_type == OP_TYPE_SYNC) {
                    il.AddInstruction(il.Nop());
                } else if (instr->op_type == OP_TYPE_RET) {
                    il.AddInstruction(il.Return(il.Register(4,this->GetLinkRegister())));
                } else if (instr->op_type == OP_TYPE_TRAP) {
                    il.AddInstruction(il.Return(il.Unimplemented())); // TODO implement as indirect jump?
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
                } else if (instr->op_type == OP_TYPE_RJMP) {
                    if (addr == 0x11b409e) {
                        LogInfo("GOT INSTR %s at 0x%x", instr->name, (uint32_t) addr);
                    }
                    //il.AddInstruction(il.Jump(il.Register(4, CTR_REG)));
                    //il.MarkLabel(false_tag);
                    il.SetIndirectBranches({ ArchAndAddr(this, addr) }); // TODO this does not work
                } else if (instr->op_type == OP_TYPE_CCALL) {
                    uint32_t value;
                    if (instr->fields[0].type == TYPE_JMP) {
                        // True branch
                        true_label = il.GetLabelForAddress(this, instr->fields[0].value);
                        value = instr->fields[0].value;
                    } else if (instr->fields[0].type == TYPE_CR) {
                        // True branch

                        true_label = il.GetLabelForAddress(this, instr->fields[1].value);
                        value = instr->fields[1].value;
                    } else {
                        return false;
                    }
                    
                    // False Branch
                    false_label = il.GetLabelForAddress(this, ((uint32_t) addr + instr->size));
                    
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
                    };
                    if (true_label && false_label)
                        il.AddInstruction(il.If(condition,*true_label,*false_label));            
                    else if (true_label)
                        il.AddInstruction(il.If(condition,*true_label,false_tag));
                    else if (false_label)
                        il.AddInstruction(il.If(condition,true_tag,*false_label));
                    else
                        il.AddInstruction(il.If(condition,true_tag,false_tag));

                    if (!true_label) {
                        il.MarkLabel(true_tag);
                    }
                    il.AddInstruction(il.Call(il.ConstPointer(4,value)));
                    if (!false_label) {
                        il.MarkLabel(false_tag);
                    }

                } else if (instr->op_type == OP_TYPE_CJMP) {
                    int value;
                    if (instr->fields[0].type == TYPE_JMP) {
                        // True branch
                        true_label = il.GetLabelForAddress(this, instr->fields[0].value);
                        value = instr->fields[0].value;
                        
                    } else if (instr->fields[0].type == TYPE_CR) {
                        // True branch
                        true_label = il.GetLabelForAddress(this, instr->fields[1].value);
                        value = instr->fields[1].value;
                        
                    } else {
                        return false;
                    }
                    
                    // False Branch
                    false_label = il.GetLabelForAddress(this, ((uint32_t) addr + instr->size));
                    
                    // TODO conditions may need to be split
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

                    // Conditions using counter register
                    if (strcmp(instr_name,"e_bdnz") == 0) {
                        // Not equal to zero
                        condition = il.CompareNotEqual(
                                4,
                                il.Register(
                                    4,
                                    CTR_REG
                                ),
                                il.Const(
                                    4,
                                    0
                                )
                            );
                        // Decrement the counter
                        il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    CTR_REG,
                                    il.Sub(
                                        4,
                                        il.Register(
                                            4,
                                            CTR_REG
                                        ),
                                        il.Const(
                                            4,
                                            1
                                        )
                                    )
                                )
                            );
                    } else if (strcmp(instr_name,"e_bdz") == 0) {
                        // Eequal to zero
                        condition = il.CompareEqual(
                                4,
                                il.Register(
                                    4,
                                    CTR_REG
                                ),
                                il.Const(
                                    4,
                                    0
                                )
                            );
                        // Decrement the counter
                        il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    CTR_REG,
                                    il.Sub(
                                        4,
                                        il.Register(
                                            4,
                                            CTR_REG
                                        ),
                                        il.Const(
                                            4,
                                            1
                                        )
                                    )
                                )
                            );
                    }

                    if (true_label && false_label)
                        il.AddInstruction(il.If(condition,*true_label,*false_label));            
                    else if (true_label)
                        il.AddInstruction(il.If(condition,*true_label,false_tag));
                    else if (false_label)
                        il.AddInstruction(il.If(condition,true_tag,*false_label));
                    else
                        il.AddInstruction(il.If(condition,true_tag,false_tag));

                    if (!true_label) {
                        il.MarkLabel(true_tag);
                        LogInfo("LOOK AT 0x%x",(uint32_t)addr);
                    }

                    il.AddInstruction(il.Jump(il.ConstPointer(4,value)));
                    
                    if (!false_label) {
                        il.MarkLabel(false_tag);
                    }
                
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
                    //LogInfo("%s AT 0x%x", instr_name, (uint32_t)addr);
                } else if (strcmp(instr_name,"e_li") == 0 || strcmp(instr_name,"se_li") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Const(
                                4,
                                instr->fields[1].value
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_mr") == 0 || strcmp(instr_name,"se_mfar") == 0 || strcmp(instr_name,"se_mtar") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_add") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_add2i") == 0 || strcmp(instr_name,"se_addi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_add2is") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
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
                            ),
                            should_update_flags ? CR0_UNSIGNED_FLAG : 0
                        )
                    );
                } else if (strcmp(instr_name,"e_add16i") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                    
                } else if (strcmp(instr_name,"e_addi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    this->get_r_reg(instr->fields[2].value)
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_stwu") == 0) {
                    il.AddInstruction(
                        il.Store(
                            4,
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_sthu") == 0) {
                    il.AddInstruction(
                        il.Store(
                            2,
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[1].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_stbu") == 0) {
                    il.AddInstruction(
                        il.Store(
                            1,
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[1].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_stw") == 0) {
                    il.AddInstruction(
                        il.Store(
                            4,
                            il.Add(
                                4,
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                }else if (strcmp(instr_name,"se_stw") == 0) {
                    il.AddInstruction(
                        il.Store(
                            4,
                            il.Add(
                                4,
                                il.ZeroExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_sth") == 0) {
                    il.AddInstruction(
                        il.Store(
                            2,
                            il.Add(
                                4,
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_sth") == 0 ) {
                    il.AddInstruction(
                        il.Store(
                            2,
                            il.Add(
                                4,
                                il.ZeroExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_stb") == 0) {
                    il.AddInstruction(
                        il.Store(
                            1,
                            il.Add(
                                4,
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_stb") == 0) {
                    il.AddInstruction(
                        il.Store(
                            1,
                            il.Add(
                                4,
                                il.ZeroExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_lwz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                4,
                                il.Add(
                                    4,
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                } else if (strcmp(instr_name,"e_lwz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                4,
                                il.Add(
                                    4,
                                    il.SignExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                } else if (strcmp(instr_name,"e_lhz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                2,
                                il.Add(
                                    4,
                                    il.SignExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                } else if (strcmp(instr_name,"se_lhz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                2,
                                il.Add(
                                    4,
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                } else if (strcmp(instr_name,"se_lbz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                1,
                                il.Add(
                                    4,
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                } else if (strcmp(instr_name,"e_lbz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                1,
                                il.Add(
                                    4,
                                    il.SignExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                } else if (strcmp(instr_name,"e_lbzu") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                1,
                                il.Add(
                                    4,
                                    il.SignExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lhzu") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                2,
                                il.Add(
                                    4,
                                    il.SignExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lwzu") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Load(
                                4,
                                il.Add(
                                    4,
                                    il.SignExtend(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )

                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.SignExtend(
                                    4,
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_cmp") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"e_cmph") == 0 || strcmp(instr_name,"se_cmph") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.SignExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            ),
                            il.SignExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"se_cmphl") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.ZeroExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            ),
                            il.ZeroExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"se_cmphl16i") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.ZeroExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            ),
                            il.ZeroExtend(
                                4,
                                il.Const(
                                    2,
                                    instr->fields[1].value
                                )
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"se_cmpi") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            il.Const(
                                4,
                                instr->fields[1].value
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"se_cmpl") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    //LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                } else if (strcmp(instr_name,"se_cmpli") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            il.Const(
                                4,
                                instr->fields[1].value
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                } else if (strcmp(instr_name,"e_cmpli") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Const(
                                4,
                                instr->fields[2].value
                            ),
                            cr_unsigned_array[instr->fields[0].value]
                        )
                    );
                } else if (strcmp(instr_name,"e_cmpl16i") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            il.Const(
                                4,
                                instr->fields[1].value
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"e_cmpi") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Const(
                                4,
                                instr->fields[2].value
                            ),
                            (cr_unsigned_array[instr->fields[0].value] - 1) // signed variant is always -1
                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                } else if (strcmp(instr_name,"se_extzb") == 0) {
                    il.AddInstruction(
                        il.ZeroExtend(
                            1,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_extzh") == 0) {
                    il.AddInstruction(
                        il.ZeroExtend(
                            2,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_extsb") == 0) {
                    il.AddInstruction(
                        il.SignExtend(
                            1,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_extsh") == 0) {
                    il.AddInstruction(
                        il.SignExtend(
                            2,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                
                } else if (strcmp(instr_name,"e_mulli") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Mult(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                )
                            )
                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);*/
                } else if (strcmp(instr_name,"e_mull2i") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Mult(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_mullw") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Mult(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_neg") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Neg(
                                4,
                                il.Add( // TODO is this correct?
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[0].value)
                                    ),
                                    il.Const(
                                        4,
                                        1
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_not") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Not(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_or") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Or(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_ori") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Or(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_or2i") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Or(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_or2is") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Or(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
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
                        )
                    );
                    
                } else if (strcmp(instr_name,"e_rlw") == 0) {
                    il.SetRegister(
                        4,
                        this->get_r_reg(instr->fields[0].value),
                        il.RotateLeft(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[2].value)
                            ),
                            should_update_flags ? CR0_UNSIGNED_FLAG : 0
                        )
                    );
                } else if (strcmp(instr_name,"e_rlwi") == 0) {
                    il.SetRegister(
                        4,
                        this->get_r_reg(instr->fields[0].value),
                        il.RotateLeft(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[1].value)
                            ),
                            il.Const(
                                4,
                                instr->fields[2].value
                            ),
                            should_update_flags ? CR0_UNSIGNED_FLAG : 0
                        )
                    );
                } else if (strcmp(instr_name,"e_rlwinm") == 0) {
                    //011b408a
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.RotateLeft(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                        ),
                                    il.Const(
                                        4,
                                        instr->fields[2].value
                                    )
                                ),
                                il.Const(
                                    4,
                                    ((1 << (instr->fields[4].value - instr->fields[3].value + 1)) - 1) << (31 - instr->fields[4].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_rlwimi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Or(
                                4,
                                il.And(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[0].value)
                                    ),
                                    il.Not(
                                        4,
                                        il.Const(
                                            4,
                                            ((1 << (instr->fields[4].value - instr->fields[3].value + 1)) - 1) << (31 - instr->fields[4].value)
                                        )
                                    )
                                ),
                                il.And(
                                    4,
                                    il.RotateLeft(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                            ),
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    ),
                                    il.Const(
                                        4,
                                        ((1 << (instr->fields[4].value - instr->fields[3].value + 1)) - 1) << (31 - instr->fields[4].value)
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_slwi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ShiftLeft(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                    /*
                    LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                } else if (strcmp(instr_name,"se_slw") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ShiftLeft(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_slwi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ShiftLeft(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_sraw") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ArithShiftRight(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_srawi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ArithShiftRight(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            )
                        )
                    );
                    
                } else if (strcmp(instr_name,"e_srwi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.LogicalShiftRight(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                    
                } else if (strcmp(instr_name,"se_srw") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.LogicalShiftRight(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            )
                        )
                    );
                    
                } else if (strcmp(instr_name,"se_srwi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.LogicalShiftRight(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_stmw") == 0) {
                    int offset_counter = instr->fields[2].value;
                    for (int i = instr->fields[0].value; i < 32; i++) {
                        il.AddInstruction(
                            il.Store(
                                4,
                                il.Add(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    ),
                                    il.Const(
                                        4,
                                        offset_counter
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(i)
                                )
                            )
                        );
                        offset_counter += 4;
                    }
                    
                } else if (strcmp(instr_name,"se_sub") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Sub(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                )
                            )
                        )
                    );

                } else if (strcmp(instr_name,"se_subf") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Sub(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_subfic") == 0) {
                    il.AddInstruction( // TODO carry?
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Sub(
                                4,
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_subi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Sub(
                                4,
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_xori") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Xor(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );

                } else if (strcmp(instr_name,"se_mtlr") == 0) {
                    //this->GetLinkRegister()
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->GetLinkRegister(),
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lmw") == 0) {
                    int offset_counter = instr->fields[2].value;
                    for (int i = instr->fields[0].value; i < 32; i++) {
                        il.AddInstruction(
                            il.SetRegister(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(i)
                                ),
                                il.Load(
                                    4,
                                    il.Add(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Const(
                                            4,
                                            offset_counter
                                        )
                                    )
                                )
                            )
                        );
                        offset_counter += 4;
                    }

                } else if (strcmp(instr_name,"se_and") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_andi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_andc") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Neg(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_andi") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_and2i") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_and2is") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
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
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );
                } else if (strcmp(instr_name,"se_bmaski") == 0) {
                    if (instr->fields[1].value == 0) { // All 1 in case of 0
                        il.AddInstruction(
                            il.SetRegister(
                                4,
                                this->get_r_reg(instr->fields[0].value),
                                il.Const(
                                    4,
                                    0xFFFFFFFF
                                )
                            )
                        );                        
                    }
                    else {
                        il.AddInstruction(
                            il.SetRegister(
                                4,
                                this->get_r_reg(instr->fields[0].value),
                                il.Const(
                                    4,
                                    (1 << (instr->fields[1].value + 1)) - 1
                                )
                            )
                        );          
                    }

                } else if (strcmp(instr_name,"e_lha") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.SignExtend(
                                4,
                                il.Load(
                                    2,
                                    il.Add(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lhau") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.SignExtend(
                                4,
                                il.Load(
                                    2,
                                    il.Add(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    )
                                )
                            )
                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[1].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lhz") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ZeroExtend(
                                4,
                                il.Load(
                                    2,
                                    il.Add(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lhzu") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ZeroExtend(
                                4,
                                il.Load(
                                    2,
                                    il.Add(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        )
                                    )
                                )
                            )
                        )
                    );
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[1].value),
                            il.Add(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_lhzu") == 0) {
                    il.AddInstruction(
                        il.SystemCall()
                    );
                } else if (strcmp(instr_name,"se_btsti") == 0) {
                    il.AddInstruction(
                        il.SetFlag(
                            CR0_UNSIGNED_FLAG, // TODO fix when I figure out on how flags work
                            il.TestBit( // TODO is the order of params correct?
                                4, 
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            )
                        )
                    );
                    /*LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);*/
                    //0107f1a8
                } else if (strcmp(instr_name,"se_bseti") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.Or(
                                4,
                                il.ZeroExtend(
                                    4,
                                    il.ShiftLeft(
                                        4,
                                        il.Const(
                                            4,
                                            1
                                        ),
                                        il.Const(
                                            4,
                                            instr->fields[1].value
                                        )
                                    )
                                ),
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            )
                            
                        )
                    );
                } else if (strcmp(instr_name,"se_bgeni") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.ZeroExtend(
                                4,
                                il.ShiftLeft(
                                    4,
                                    il.Const(
                                        4,
                                        1
                                    ),
                                    il.Const(
                                        4,
                                        instr->fields[1].value
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_addic") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.AddCarry(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[1].value)
                                ),
                                il.Const(
                                    4,
                                    instr->fields[2].value
                                ),
                                il.Flag(
                                    IL_FLAG_XER_CA
                                ),
                                should_update_flags ? CR0_UNSIGNED_FLAG : 0
                            )
                        )
                    );

                } else if (strcmp(instr_name,"se_bclri") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_r_reg(instr->fields[0].value),
                            il.And(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                ),
                                il.Const(
                                    4,
                                    ~((1 << (31 - 6)) & 0xffffffff)
                                )
                            )
                        )
                    );

                } else if (strcmp(instr_name,"e_cmphl16i") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.ZeroExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            ),
                            il.ZeroExtend(
                                4,
                                il.Const(
                                    2,
                                    instr->fields[1].value
                                )
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"e_cmp16i") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.SignExtend(
                                4,
                                il.Register(
                                    4,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            ),
                            il.SignExtend(
                                4,
                                il.Const(
                                    4,
                                    instr->fields[1].value
                                )
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"se_sc") == 0) {
                    il.AddInstruction(il.SystemCall());
                } else if (strcmp(instr_name,"e_cmph16i") == 0) {
                    il.AddInstruction(
                        il.Sub(
                            4,
                            il.SignExtend(
                                4,
                                il.Register(
                                    2,
                                    this->get_r_reg(instr->fields[0].value)
                                )
                            ),
                            il.SignExtend(
                                4,
                                il.Const(
                                    2,
                                    instr->fields[1].value
                                )
                            ),
                            CR0_UNSIGNED_FLAG
                        )
                    );
                } else if (strcmp(instr_name,"e_crand") == 0) {
                    il.AddInstruction(il.Unimplemented());
                    // TODO find how to map this to correct registers
                    il.AddInstruction(
                        il.SetFlag(
                            this->get_cr_reg(instr->fields[0].value),
                            il.And(
                                0,
                                il.Flag(
                                    this->get_cr_reg(instr->fields[1].value)
                                ),
                                il.Flag(
                                    this->get_cr_reg(instr->fields[2].value)
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_crandc") == 0) {
                    //il.AddInstruction(il.Unimplemented());
                    //TODO find how to map this to correct registers
                    //return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
                    il.AddInstruction(
                        il.SetFlag(
                            this->get_cr_reg(instr->fields[0].value),
                            il.And(
                                0,
                                il.Flag(
                                    this->get_cr_reg(instr->fields[1].value)
                                ),
                                il.Not(
                                    0,
                                    il.Flag(
                                        this->get_cr_reg(instr->fields[2].value)
                                    )
                                )
                            )
                        )
                    );
                } else if (strcmp(instr_name,"e_mcrf") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            this->get_cr_reg(instr->fields[0].value),
                            il.Register(
                                4,
                                this->get_cr_reg(instr->fields[1].value)
                            )
                        )
                    );

                } else if (false) {

                } else if (false) {

                } else if (false) {

                } else if (false) {

                } else if (false) {

                } else if (false) {

                } else if (false) {

                } else if (false) {

                } else if (false) {
                    // TODO e_crand
                    // TODO e_beql
                    // TODO 011b409e se_bctr
                    LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                    LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                    LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                    LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);
                } else if (strcmp(instr_name,"se_illegal") == 0) {
                    il.AddInstruction(il.Trap(0));
                } else {
                    LogInfo("NOT LIFTED %s AT 0x%x", instr_name, (uint32_t)addr);

                    il.AddInstruction(il.Unimplemented());
                }
                return true;
            } else {
                // TODO these should be hadnled by PowerPC but are not
                // 011e6eb0 vaddsbs
                // Floating points
                // TODO wrteeX
                // TODO mfspr and fridends
                if (strcmp(instr_name,"cntlzw") == 0) {
                    il.AddInstruction(
                        il.Intrinsic(
                            { RegisterOrFlag::Register(this->get_r_reg(instr->fields[0].value)) }, // Outputs
                            CNTLWZ_INTRINSIC,
                            { il.Register(4, this->get_r_reg(instr->fields[1].value)) } // Inputs
                        )
                    );
                    return true;
                } else if (strcmp(instr_name,"mtmsr") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            MSR_REG,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            )
                        )
                    );
                    return true;
                } else if (strcmp(instr_name,"mfmsr") == 0) {
                    il.AddInstruction(
                        il.SetRegister(
                            4,
                            il.Register(
                                4,
                                this->get_r_reg(instr->fields[0].value)
                            ),
                            MSR_REG
                        )
                    );
                    return true;
                } else if (strcmp(instr_name,"lbzx") == 0) {
                    LogInfo("FOUND LBZX AT 0x%x",(uint32_t)addr);
                    return true;
                }
                
            }
            
        }
		return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
	}

    virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len, std::vector< InstructionTextToken > &result) override
	{
        char tmp[256] = {0};
		vle_t* instr;
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2) == 0) {
            //if (true) {
                len = instr->size;
                // Add instruction name
                result.emplace_back(InstructionToken, instr->name);
                result.emplace_back(TextToken, " "); //TODO align operands
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
                            result.pop_back();
                            result.pop_back();
                            sprintf(reg_str, "r%d", instr->fields[op_index-1].value); 
                            sprintf(hex_val, "0x%x", instr->fields[op_index].value); 
                            result.emplace_back(IntegerToken, hex_val, instr->fields[op_index].value);
                            result.emplace_back(OperandSeparatorToken, "(");
                            result.emplace_back(RegisterToken, reg_str);
                            result.emplace_back(OperandSeparatorToken, ")");
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
            }
			
        } 
		return ArchitectureHook::GetInstructionText(data, addr, len, result);
	}

    virtual bool GetInstructionInfo(const uint8_t *data, uint64_t addr, size_t maxLen, InstructionInfo &result) override
	{
        char tmp[256] = {0};
		vle_t* instr;
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2) == 0) {
            //if (true) {
                result.length = instr->size;
                uint32_t target;
                switch (instr->op_type) {
                    // TODO OP_TYPE_CCALL??
                    case OP_TYPE_JMP:
                        result.AddBranch(UnconditionalBranch,(instr->fields[0].value));// + (uint32_t) addr) & 0xffffffff);
                        break;
                    case OP_TYPE_CJMP:
                        if (instr->fields[0].type == TYPE_JMP) {
                            result.AddBranch(TrueBranch, instr->fields[0].value);// + (uint32_t) addr) & 0xffffffff);
                            result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                        } else if (instr->fields[0].type == TYPE_CR) {
                            //result.AddBranch(IndirectBranch);
                            result.AddBranch(TrueBranch,(instr->fields[1].value));// + (uint32_t) addr) & 0xffffffff);
                            result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                        } else {
                            return false;
                        }
                        break;
                    case OP_TYPE_CCALL:
                        if (instr->fields[0].type == TYPE_JMP) {
                            result.AddBranch(CallDestination, instr->fields[0].value);// + (uint32_t) addr) & 0xffffffff);
                            result.AddBranch(FalseBranch,(instr->size + addr) & 0xffffffff);
                        } else if (instr->fields[0].type == TYPE_CR) {
                            //result.AddBranch(IndirectBranch);
                            result.AddBranch(CallDestination,(instr->fields[1].value));// + (uint32_t) addr) & 0xffffffff);
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
            }
			
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