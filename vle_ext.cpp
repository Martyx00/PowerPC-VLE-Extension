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
#define PPC_REG_MSR 152 

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
    CNTLWZ_INTRINSIC,
    E_STMVGPRW_INTRINSIC,
    E_LDMVGPRW_INTRINSIC
};

// TODO add floating point instructions 0x11986ca
// TODO add evfsmulx and others (look at IDA) 0115DDD0
// TODO MTSPR decoding
// TODO e_bc and e_bcl e_bdz and e_bdzl signed jump value - check correctness.

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

    insn_names get_insn(std::string const& insn_name) {
        if (insn_name == "se_mtctr") return SE_MTCTR;
        if (insn_name == "se_mfctr") return SE_MFCTR;
        if (insn_name == "se_mflr") return SE_MFLR;
        if (insn_name == "se_mtspr") return SE_MTSPR;
        if (insn_name == "se_mfspr") return SE_MFSPR;
        if (insn_name == "se_bctr") return SE_BCTR;
        if (insn_name == "se_bctrl") return SE_BCTRL;
        if (insn_name == "e_lis") return E_LIS;
        if (insn_name == "e_li") return E_LI;
        if (insn_name == "se_li") return SE_LI;
        if (insn_name == "se_mr") return SE_MR;
        if (insn_name == "se_mfar") return SE_MFAR;
        if (insn_name == "se_mtar") return SE_MTAR;
        if (insn_name == "se_add") return SE_ADD;
        if (insn_name == "e_add2i") return E_ADD2I;
        if (insn_name == "se_addi") return SE_ADDI;
        if (insn_name == "e_add2is") return E_ADD2IS;
        if (insn_name == "e_add16i") return E_ADD16I;
        if (insn_name == "e_addi") return E_ADDI;
        if (insn_name == "e_stwu") return E_STWU;
        if (insn_name == "e_sthu") return E_STHU;
        if (insn_name == "e_stbu") return E_STBU;
        if (insn_name == "e_stw") return E_STW;
        if (insn_name == "se_stw") return SE_STW;
        if (insn_name == "e_sth") return E_STH;
        if (insn_name == "se_sth") return SE_STH;
        if (insn_name == "e_stb") return E_STB;
        if (insn_name == "se_stb") return SE_STB;
        if (insn_name == "se_lwz") return SE_LWZ;
        if (insn_name == "e_lwz") return E_LWZ;
        if (insn_name == "e_lhz") return E_LHZ;
        if (insn_name == "se_lhz") return SE_LHZ;
        if (insn_name == "se_lbz") return SE_LBZ;
        if (insn_name == "e_lbz") return E_LBZ;
        if (insn_name == "e_lbzu") return E_LBZU;
        if (insn_name == "e_lhzu") return E_LHZU;
        if (insn_name == "e_lwzu") return E_LWZU;
        if (insn_name == "se_cmp") return SE_CMP;
        if (insn_name == "e_cmph") return E_CMPH;
        if (insn_name == "se_cmph") return SE_CMPH;
        if (insn_name == "se_cmphl") return SE_CMPHL;
        if (insn_name == "se_cmphl16i") return SE_CMPHL16I;
        if (insn_name == "se_cmpi") return SE_CMPI;
        if (insn_name == "se_cmpl") return SE_CMPL;
        if (insn_name == "se_cmpli") return SE_CMPLI;
        if (insn_name == "e_cmpli") return E_CMPLI;
        if (insn_name == "e_cmpl16i") return E_CMPL16I;
        if (insn_name == "e_cmpi") return E_CMPI;
        if (insn_name == "se_extzb") return SE_EXTZB;
        if (insn_name == "se_extzh") return SE_EXTZH;
        if (insn_name == "se_extsb") return SE_EXTSB;
        if (insn_name == "se_extsh") return SE_EXTSH;
        if (insn_name == "e_mulli") return E_MULLI;
        if (insn_name == "e_mull2i") return E_MULL2I;
        if (insn_name == "se_mullw") return SE_MULLW;
        if (insn_name == "se_neg") return SE_NEG;
        if (insn_name == "se_not") return SE_NOT;
        if (insn_name == "se_or") return SE_OR;
        if (insn_name == "e_ori") return E_ORI;
        if (insn_name == "e_or2i") return E_OR2I;
        if (insn_name == "e_or2is") return E_OR2IS;
        if (insn_name == "e_rlw") return E_RLW;
        if (insn_name == "e_rlwi") return E_RLWI;
        if (insn_name == "e_rlwinm") return E_RLWINM;
        if (insn_name == "e_rlwimi") return E_RLWIMI;
        if (insn_name == "e_slwi") return E_SLWI;
        if (insn_name == "se_slw") return SE_SLW;
        if (insn_name == "se_slwi") return SE_SLWI;
        if (insn_name == "se_sraw") return SE_SRAW;
        if (insn_name == "se_srawi") return SE_SRAWI;
        if (insn_name == "e_srwi") return E_SRWI;
        if (insn_name == "se_srw") return SE_SRW;
        if (insn_name == "se_srwi") return SE_SRWI;
        if (insn_name == "e_stmw") return E_STMW;
        if (insn_name == "se_sub") return SE_SUB;
        if (insn_name == "se_subf") return SE_SUBF;
        if (insn_name == "e_subfic") return E_SUBFIC;
        if (insn_name == "se_subi") return SE_SUBI;
        if (insn_name == "e_xori") return E_XORI;
        if (insn_name == "se_mtlr") return SE_MTLR;
        if (insn_name == "e_lmw") return E_LMW;
        if (insn_name == "se_and") return SE_AND;
        if (insn_name == "se_andi") return SE_ANDI;
        if (insn_name == "se_andc") return SE_ANDC;
        if (insn_name == "e_andi") return E_ANDI;
        if (insn_name == "e_and2i") return E_AND2I;
        if (insn_name == "e_and2is") return E_AND2IS;
        if (insn_name == "se_bmaski") return SE_BMASKI;
        if (insn_name == "e_lha") return E_LHA;
        if (insn_name == "e_lhau") return E_LHAU;
        if (insn_name == "se_btsti") return SE_BTSTI;
        if (insn_name == "se_bseti") return SE_BSETI;
        if (insn_name == "se_bgeni") return SE_BGENI;
        if (insn_name == "e_addic") return E_ADDIC;
        if (insn_name == "se_bclri") return SE_BCLRI;
        if (insn_name == "e_cmphl16i") return E_CMPHL16I;
        if (insn_name == "e_cmp16i") return E_CMP16I;
        if (insn_name == "se_sc") return SE_SC;
        if (insn_name == "e_cmph16i") return E_CMPH16I;
        if (insn_name == "e_crand") return E_CRAND;
        if (insn_name == "e_crandc") return E_CRANDC;
        if (insn_name == "e_mcrf") return E_MCRF;
        if (insn_name == "efsabs") return EFSABS;
        if (insn_name == "efsadd") return EFSADD;
        if (insn_name == "efscfh") return EFSCFH;
        if (insn_name == "efscfsf") return EFSCFSF;
        if (insn_name == "efscfsi") return EFSCFSI;
        if (insn_name == "efscfuf") return EFSCFUF;
        if (insn_name == "efscfui") return EFSCFUI;
        if (insn_name == "efscmpgt") return EFSCMPGT;
        if (insn_name == "efscmpeq") return EFSCMPEQ;
        if (insn_name == "efscmplt") return EFSCMPLT;
        if (insn_name == "efscth") return EFSCTH;
        if (insn_name == "efsctsf") return EFSCTSF;
        if (insn_name == "efsctsi") return EFSCTSI;
        if (insn_name == "efsctsiz") return EFSCTSIZ;
        if (insn_name == "efsctuf") return EFSCTUF;
        if (insn_name == "efsctui") return EFSCTUI;
        if (insn_name == "efsctuiz") return EFSCTUIZ;
        if (insn_name == "efsdiv") return EFSDIV;
        if (insn_name == "efsmadd") return EFSMADD;
        if (insn_name == "efsmax") return EFSMAX;
        if (insn_name == "efsmin") return EFSMIN;
        if (insn_name == "efsmsub") return EFSMSUB;
        if (insn_name == "efsmul") return EFSMUL;
        if (insn_name == "efsnabs") return EFSNABS;
        if (insn_name == "efsneg") return EFSNEG;
        if (insn_name == "efsnmadd") return EFSNMADD;
        if (insn_name == "efsnmsub") return EFSNMSUB;
        if (insn_name == "efssqrt") return EFSSQRT;
        if (insn_name == "efssub") return EFSSUB;
        if (insn_name == "efststeq") return EFSTSTEQ;
        if (insn_name == "efststgt") return EFSTSTGT;
        if (insn_name == "efststlt") return EFSTSTLT;
        if (insn_name == "e_ldmvgprw") return E_LDMVGPRW;
        if (insn_name == "e_stmvgprw") return E_STMVGPRW;
        if (insn_name == "se_illegal") return SE_ILLEGAL;
        return INVALID_INSN;
    }

    // Registers override
	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> result = ArchitectureHook::GetAllRegisters();
        result.push_back(PPC_REG_MSR);
		return result;
	}


	virtual std::vector<uint32_t> GetGlobalRegisters() override
	{
		//return vector<uint32_t>{ PPC_REG_R2, PPC_REG_R13, PPC_REG_MSR };
        vector<uint32_t> result = ArchitectureHook::GetGlobalRegisters();
        result.push_back(PPC_REG_MSR);
        return result;
	}


	BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}


	virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
	{
		//MYLOG("%s(%s)\n", __func__, powerpc_reg_to_str(regId));

		switch(regId) {
			// BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset,
			//   size_t size, bool zeroExtend = false)
            case PPC_REG_MSR: return RegisterInfo(PPC_REG_MSR, 0 ,4);
			default:
				//LogError("%s(%d == \"%s\") invalid argument", __func__,
				//  regId, powerpc_reg_to_str(regId));
				return ArchitectureHook::GetRegisterInfo(regId);
		}
	}

    //------------------------------------------------------------------------------

    virtual std::string GetIntrinsicName (uint32_t intrinsic) override {
         switch (intrinsic)  {
            case CNTLWZ_INTRINSIC:
                return "CountLeadingZeros";
            case E_STMVGPRW_INTRINSIC:
                return "Store (R0, R3:R12)";
            case E_LDMVGPRW_INTRINSIC:
                return "Load (R0, R3:R12)";
            default:
                return "";
            }
    }

    virtual std::vector<uint32_t> GetAllIntrinsics() override {
        return vector<uint32_t> {
            CNTLWZ_INTRINSIC,
            E_STMVGPRW_INTRINSIC
        };
    }

    virtual std::vector<NameAndType> GetIntrinsicInputs (uint32_t intrinsic) override {
        switch (intrinsic)
            {
                case CNTLWZ_INTRINSIC:
                    return {
                        NameAndType("WORD", Type::IntegerType(4, false))
                    };
                case E_STMVGPRW_INTRINSIC:
                    return {
                        NameAndType("At", Type::IntegerType(4, false))
                    };
                case E_LDMVGPRW_INTRINSIC:
                    return {
                        NameAndType("From", Type::IntegerType(4, false))
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
                case E_STMVGPRW_INTRINSIC:
                    return { };
                    //return vector<Confidence<Ref<Type>>>();
                case E_LDMVGPRW_INTRINSIC:
                    return {
                        /*Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false),
                        Type::IntegerType(4, false)*/
                    };
                default:
                    return vector<Confidence<Ref<Type>>>();
            }
    }

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
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
        
        if ((instr = vle_decode_one(data, 4,(uint32_t) addr))) {
            strncpy(instr_name,instr->name,49);
            //LogInfo("FOR %s GOT %d || %d", instr_name,strncmp(instr_name, "se_",3) == 0, strncmp(instr_name, "e_", 2) == 0);
            len = instr->size;
            //LogError("Processing %s at 0x%x,",instr_name, addr);
            if (strncmp(instr_name, "se_",3) == 0 || strncmp(instr_name, "e_", 2) == 0 || strncmp(instr->name, "ef",2) == 0 || strncmp(instr->name, "ev",2) == 0) {
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
                } else if (instr->op_type == OP_TYPE_RJMP) {
                    if (addr == 0x11b409e) {
                        LogInfo("GOT INSTR %s at 0x%x", instr->name, (uint32_t) addr);
                    }
                    il.AddInstruction(il.Jump(il.Register(4, CTR_REG)));
                    il.MarkLabel(false_tag);
                    //il.SetIndirectBranches({ ArchAndAddr(this, addr) }); // TODO this does not work
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

                    if (strcmp(instr_name,"e_bdnzl") == 0) {
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
                    } else if (strcmp(instr_name,"e_bdzl") == 0) {
                        // Equal to zero
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
                        // Equal to zero
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
                    }

                    il.AddInstruction(il.Jump(il.ConstPointer(4,value)));

                    if (!false_label) {
                        il.MarkLabel(false_tag);
                    }
                
                } else {
                    switch (this->get_insn(instr_name))
                    {
                    case SE_MTCTR:
                        {
                            il.AddInstruction(il.SetRegister(4, CTR_REG, il.Register(4, this->get_r_reg(instr->fields[0].value))));
                        }
                        break;
                    case SE_MFCTR:
                        {
                            il.AddInstruction(il.SetRegister(4, this->get_r_reg(instr->fields[0].value), il.Register(4, CTR_REG)));
                        }
                        break;
                    case SE_MFLR:
                        {
                            il.AddInstruction(il.SetRegister(4, this->get_r_reg(instr->fields[0].value), il.Register(4, this->GetLinkRegister())));
                        }
                        break;
                    case SE_MTSPR:
                        {
                            il.AddInstruction(il.SetRegister(4, CTR_REG, il.Register(4, this->get_r_reg(instr->fields[0].value))));
                        }
                        break;
                    case SE_MFSPR:
                        {
                            il.AddInstruction(il.SetRegister(4, this->get_r_reg(instr->fields[0].value), il.Register(4, CTR_REG)));
                        }
                        break;
                    case SE_BCTR:
                        {
                            il.AddInstruction(il.Jump(il.Register(4, CTR_REG)));
                        }
                        break;
                    case SE_BCTRL:
                        {
                            il.AddInstruction(il.Call(il.Register(4, CTR_REG)));
                        }
                        break;
                    case E_LIS:
                        {
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
                        }
                        break;
                    case E_LI:
                    case SE_LI:
                        {
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
                        }
                        break;
                    case SE_MR:
                    case SE_MFAR:
                    case SE_MTAR:
                        {
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
                        }
                        break;
                    case SE_ADD:
                        {
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
                        }
                        break;
                    case E_ADD2I:
                    case SE_ADDI:
                        {
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
                        }
                        break;
                    case E_ADD2IS:
                        {
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
                        }
                        break;
                    case E_ADD16I:
                        {
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
                                                2,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_ADDI:
                        {
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
                                        il.ZeroExtend(
                                            4,
                                            il.Const(
                                                1,
                                                instr->fields[2].value
                                            )
                                        ),
                                        
                                        should_update_flags ? CR0_UNSIGNED_FLAG : 0
                                    )
                                )
                            );
                        }
                        break;
                    case E_STWU:
                        {
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
                                                1,
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
                                                1,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_STHU:
                        {
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
                                                1,
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
                                                1,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_STBU:
                        {
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
                                                1,
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
                                                1,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_STW:
                        {
                            il.AddInstruction(
                                il.Store(
                                    4,
                                    il.Add(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                2,
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
                        }
                        break;
                    case SE_STW:
                        {
                            il.AddInstruction(
                                il.Store(
                                    4,
                                    il.Add(
                                        4,
                                        il.ZeroExtend(
                                            4,
                                            il.Const(
                                                1,
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
                        }
                        break;
                    case E_STH:
                        {
                            il.AddInstruction(
                                il.Store(
                                    2,
                                    il.Add(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                2,
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
                        }
                        break;
                    case SE_STH:
                        {
                            il.AddInstruction(
                                il.Store(
                                    2,
                                    il.Add(
                                        4,
                                        il.ZeroExtend(
                                            4,
                                            il.Const(
                                                1,
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
                        }
                        break;
                    case E_STB:
                        {
                            il.AddInstruction(
                                il.Store(
                                    1,
                                    il.Add(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                2,
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
                        }
                        break;
                    case SE_STB:
                        {
                            il.AddInstruction(
                                il.Store(
                                    1,
                                    il.Add(
                                        4,
                                        il.ZeroExtend(
                                            4,
                                            il.Const(
                                                1,
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
                        }
                        break;
                    case SE_LWZ:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.Load(
                                        4,
                                        il.Add(
                                            4,
                                            //il.ZeroExtend(
                                            //    4,
                                                il.Const(
                                                    4,
                                                    instr->fields[2].value
                                            //    )
                                            ),
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )

                                )
                            );
                        }
                        break;
                    case E_LWZ:
                        {
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
                                                    2,
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
                        }
                        break;
                    case E_LHZ:
                        {
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
                                                    2,
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
                        }
                        break;
                    case SE_LHZ:
                        {
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
                                                    1,
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
                        }
                        break;
                    case SE_LBZ:
                        {
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
                                                    1,
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
                        }
                        break;
                    case E_LBZ:
                        {
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
                                                    2,
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
                        }
                        break;
                    case E_LBZU:
                        {
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
                                                    2,
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
                                                2,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                     case E_LHZU:
                        {
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
                                                    2,
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
                                                2,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                     case E_LWZU:
                        {
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
                                                    2,
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
                                                2,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                     case SE_CMP:
                        {
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
                        }
                        break;
                     case E_CMPH:
                     case SE_CMPH:
                        {
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
                        }
                        break;
                     case SE_CMPHL:
                        {
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
                        }
                        break;
                     case SE_CMPHL16I:
                        {
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
                        }
                        break;
                     case SE_CMPI:
                        {
                            il.AddInstruction(
                                il.Sub(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[0].value)
                                    ),
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            1,
                                            instr->fields[1].value
                                        )
                                    ),
                                    CR0_UNSIGNED_FLAG
                                )
                            );
                        }
                        break;
                    case SE_CMPL:
                        {
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
                        }
                        break;
                    case SE_CMPLI:
                        {
                            il.AddInstruction(
                                il.Sub(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[0].value)
                                    ),
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            1,
                                            instr->fields[1].value
                                        )
                                    ),
                                    CR0_UNSIGNED_FLAG
                                )
                            );
                        }
                        break;
                    case E_CMPLI:
                        {
                            il.AddInstruction(
                                il.Sub(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    ),
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            1,
                                            instr->fields[2].value
                                        )
                                    ),
                                    cr_unsigned_array[instr->fields[0].value]
                                )
                            );
                        }
                        break;
                    case E_CMPL16I:
                        {
                            il.AddInstruction(
                                il.Sub(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[0].value)
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
                        }
                        break;
                    case E_CMPI:
                        {
                            il.AddInstruction(
                                il.Sub(
                                    4,
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[1].value)
                                    ),
                                    il.ZeroExtend(
                                        4,
                                        il.Const(
                                            1,
                                            instr->fields[2].value
                                        )
                                    ),
                                    (cr_unsigned_array[instr->fields[0].value] - 1) // signed variant is always -1
                                )
                            );
                        }
                        break;
                    case SE_EXTZB:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.ZeroExtend(
                                        4,
                                        il.Register(
                                            1,
                                            this->get_r_reg(instr->fields[0].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_EXTZH:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.ZeroExtend(
                                        4,
                                        il.Register(
                                            2,
                                            this->get_r_reg(instr->fields[0].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_EXTSB:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.SignExtend(
                                        4,
                                        il.Register(
                                            1,
                                            this->get_r_reg(instr->fields[0].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_EXTSH:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.SignExtend(
                                        4,
                                        il.Register(
                                            2,
                                            this->get_r_reg(instr->fields[0].value)
                                        ),
                                        CR0_UNSIGNED_FLAG
                                    )
                                )
                            );
                        }
                        break;
                    case E_MULLI:
                        {
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
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                1,
                                                instr->fields[2].value
                                            )
                                        )
                                        
                                    )
                                )
                            );
                        }
                        break;
                    case E_MULL2I:
                        {
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
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                2,
                                                instr->fields[1].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_MULLW:
                        {
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
                        }
                        break;
                    case SE_NEG:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.Neg(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[0].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_NOT:
                        {
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
                        }
                        break;
                    case SE_OR:
                        {
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
                        }
                        break;
                    case E_ORI:
                        {
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
                        }
                        break;
                    case E_OR2I:
                        {
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
                        }
                        break;
                    case E_OR2IS:
                        {
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
                        }
                        break;
                    case E_RLW:
                        {
                            il.AddInstruction(
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
                                )
                            );
                        }
                        break;
                    case E_RLWI:
                        {
                            il.AddInstruction(
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
                                )
                            );
                        }
                        break;
                    case E_RLWINM:
                        {
                            if (instr->fields[2].value == 31) {
                                il.AddInstruction(
                                    il.SetRegister(
                                        4,
                                        this->get_r_reg(instr->fields[0].value),
                                        il.And(
                                            4,
                                            il.LogicalShiftRight(
                                                4,
                                                il.Register(
                                                        4,
                                                        this->get_r_reg(instr->fields[1].value)
                                                    ),
                                                il.Const(
                                                    4,
                                                    1
                                                )
                                            ),
                                            il.Const(
                                                4,
                                                ((1 << (instr->fields[4].value - instr->fields[3].value + 1)) - 1) << (31 - instr->fields[4].value)
                                            )
                                        )
                                    )
                                );
                            } else if (instr->fields[2].value == 0) {
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
                                                ((1 << (instr->fields[4].value - instr->fields[3].value + 1)) - 1) << (31 - instr->fields[4].value)
                                            )
                                        )
                                    )
                                );
                            } else {
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
                            }
                        }
                        break;
                    case E_RLWIMI:
                        {
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
                        }
                        break;
                    case E_SLWI:
                        {
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
                        }
                        break;
                    case SE_SLW:
                        {
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
                        }
                        break;
                    case SE_SLWI:
                        {
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
                        }
                        break;
                    case SE_SRAW:
                        {
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
                        }
                        break;
                    case SE_SRAWI:
                        {
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
                        }
                        break;
                    case E_SRWI:
                        {
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
                        }
                        break;
                    case SE_SRW:
                        {
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
                        }
                        break;
                    case SE_SRWI:
                        {
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
                        }
                        break;
                    case E_STMW:
                        {
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
                                            il.SignExtend(
                                                4,
                                                il.Const(
                                                    1,
                                                    offset_counter
                                                )
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
                        }
                        break;
                    case SE_SUB:
                        {
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
                        }
                        break;
                    case SE_SUBF:
                        {
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
                        }
                        break;
                    case E_SUBFIC:
                        {
                            il.AddInstruction( 
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.SubBorrow(
                                        4,
                                        il.Const(
                                            4,
                                            instr->fields[2].value
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Flag(IL_FLAG_XER_CA),
                                        should_update_flags ? CR0_UNSIGNED_FLAG : 0
                                    )
                                )
                            );
                        }
                        break;
                    case SE_SUBI:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.Sub(
                                        4,
                                        il.ZeroExtend(
                                            4,
                                            il.Const(
                                                1,
                                                instr->fields[2].value
                                            )
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        should_update_flags ? CR0_UNSIGNED_FLAG : 0
                                    )
                                )
                            );
                        }
                        break;
                    case E_XORI:
                        {
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
                        }
                        break;
                    case SE_MTLR:
                        {
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
                        }
                        break;
                    case E_LMW:
                        {
                            int offset_counter = instr->fields[2].value;
                            for (int i = instr->fields[0].value; i < 32; i++) {
                                il.AddInstruction(
                                    il.SetRegister(
                                        4,
                                        this->get_r_reg(i),
                                        il.Load(
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
                                                        1,
                                                        offset_counter
                                                    )
                                                )
                                                
                                            )
                                        )
                                    )
                                );
                                offset_counter += 4;
                            }
                        }
                        break;
                    case SE_AND:
                        {
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
                        }
                        break;
                    case SE_ANDI:
                        {
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
                        }
                        break;
                    case SE_ANDC:
                        {
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
                        }
                        break;
                    case E_ANDI:
                        {
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
                        }
                        break;
                    case E_AND2I:
                        {
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
                        }
                        break;
                    case E_AND2IS:
                        {
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
                        }
                        break;
                    case SE_BMASKI:
                        {
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
                        }
                        break;
                    case E_LHA:
                        {
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
                                                il.SignExtend(
                                                    4,
                                                    il.Const(
                                                        2,
                                                        instr->fields[2].value
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_LHAU:
                        {
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
                                                il.SignExtend(
                                                    4,
                                                    il.Const(
                                                        2,
                                                        instr->fields[2].value
                                                    )
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
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                2,
                                                instr->fields[2].value
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_BTSTI:
                        {
                            il.AddInstruction(
                                il.SetFlag(
                                    CR0_UNSIGNED_FLAG,
                                    il.Not(
                                        4,
                                        il.And(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value)
                                            ),
                                            il.Const(
                                                4,
                                                1 << (31 - instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case SE_BSETI:
                        {
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
                                                    31 - instr->fields[1].value
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
                        }
                        break;
                    case SE_BGENI:
                        {
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
                        }
                        break;
                    case E_ADDIC:
                        {
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
                        }
                        break;
                    case SE_BCLRI:
                        {
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
                                            ((1 << (31 - instr->fields[1].value)) ^ 0xffffffff)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_CMPHL16I:
                        {
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
                        }
                        break;
                    case E_CMP16I:
                        {
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
                        }
                        break;
                    case SE_SC:
                        {
                            il.AddInstruction(il.SystemCall());
                        }
                        break;
                    case E_CMPH16I:
                        {
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
                        }
                        break;
                    case E_CRAND:
                        {
                            //il.AddInstruction(il.Unimplemented());
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
                        }
                        break;
                    case E_CRANDC:
                        {
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
                        }
                        break;
                    case E_MCRF:
                        {
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
                        }
                        break;
                    case EFSABS:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatAbs(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSADD:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatAdd(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                                
                            );
                        }
                        break;
                    case EFSCFH:
                        {
                            //TODO
                            il.AddInstruction(il.Unimplemented());
                        }
                        break;
                    case EFSCFSF:
                        {
                            //TODO
                            il.AddInstruction(il.Unimplemented());
                        }
                        break;
                    case EFSCFSI:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.IntToFloat(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCFUF:
                        {
                            //TODO
                            il.AddInstruction(il.Unimplemented());
                        }
                        break;
                    case EFSCFUI:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.IntToFloat(
                                        4,
                                        il.ZeroExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCMPGT:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_cr_reg(instr->fields[0].value),
                                    il.FloatCompareGreaterThan(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        ),
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[2].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCMPEQ:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_cr_reg(instr->fields[0].value),
                                    il.FloatCompareEqual(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        ),
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[2].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCMPLT:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_cr_reg(instr->fields[0].value),
                                    il.FloatCompareLessThan(
                                        4,
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        ),
                                        il.SignExtend(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[2].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCTH:
                        {
                            //TODO
                            il.AddInstruction(il.Unimplemented());
                        }
                        break;
                    case EFSCTSF:
                        {
                            //TODO
                            il.AddInstruction(il.Unimplemented());
                        }
                        break;
                    case EFSCTSI:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.SignExtend(
                                        4,
                                        il.FloatToInt(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCTSIZ:
                        {
                            //TODO rounding?
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.SignExtend(
                                        4,
                                        il.FloatToInt(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCTUF:
                        {
                            //TODO
                            il.AddInstruction(il.Unimplemented());
                        }
                        break;
                    case EFSCTUI:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.ZeroExtend(
                                        4,
                                        il.FloatToInt(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSCTUIZ:
                        {
                            il.AddInstruction( // TODO rounding
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.ZeroExtend(
                                        4,
                                        il.FloatToInt(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSDIV:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatDiv(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSMADD:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatAdd(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[0].value)
                                        ),
                                        il.FloatMult(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            ),
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[2].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSMAX:
                        {
                            LowLevelILLabel true_tag;
                            LowLevelILLabel false_tag;
                            LowLevelILLabel end_tag;
                            il.AddInstruction(
                                il.If(
                                    il.FloatCompareGreaterEqual(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    ),
                                    true_tag,
                                    false_tag
                                )
                            );
                            il.MarkLabel(true_tag);
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
                            il.AddInstruction(il.Goto(end_tag));
                            il.MarkLabel(false_tag);
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[2].value)
                                    )
                                )
                            );
                            il.MarkLabel(end_tag);
                        }
                        break;
                    case EFSMIN:
                        {
                            LowLevelILLabel true_tag;
                            LowLevelILLabel false_tag;
                            LowLevelILLabel end_tag;
                            il.AddInstruction(
                                il.If(
                                    il.FloatCompareLessEqual(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    ),
                                    true_tag,
                                    false_tag
                                )
                            );
                            il.MarkLabel(true_tag);
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
                            il.AddInstruction(il.Goto(end_tag));
                            il.MarkLabel(false_tag);
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.Register(
                                        4,
                                        this->get_r_reg(instr->fields[2].value)
                                    )
                                )
                            );
                            il.MarkLabel(end_tag);
                        }
                        break;
                    case EFSMSUB:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatSub(
                                        4,
                                        il.FloatMult(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            ),
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[2].value)
                                            )
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[0].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSMUL:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatMult(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSNABS:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.Or(
                                        4,
                                        il.Const(
                                            4,
                                            0x80000000
                                        ),
                                        il.FloatAbs(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[1].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSNEG:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatNeg(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSNMADD:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatNeg(
                                        4,
                                        il.FloatAdd(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value)
                                            ),
                                            il.FloatMult(
                                                4,
                                                il.Register(
                                                    4,
                                                    this->get_r_reg(instr->fields[1].value)
                                                ),
                                                il.Register(
                                                    4,
                                                    this->get_r_reg(instr->fields[2].value)
                                                )
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSNMSUB:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatNeg(
                                        4,
                                        il.FloatSub(
                                            4,
                                            il.FloatMult(
                                                4,
                                                il.Register(
                                                    4,
                                                    this->get_r_reg(instr->fields[1].value)
                                                ),
                                                il.Register(
                                                    4,
                                                    this->get_r_reg(instr->fields[2].value)
                                                )
                                            ),
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value)
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSSQRT:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatSqrt(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)

                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSSUB:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(instr->fields[0].value),
                                    il.FloatSub(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSTSTEQ:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_cr_reg(instr->fields[0].value),
                                    il.FloatCompareEqual(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSTSTGT:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_cr_reg(instr->fields[0].value),
                                    il.FloatCompareGreaterThan(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case EFSTSTLT:
                        {
                            il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_cr_reg(instr->fields[0].value),
                                    il.FloatCompareLessThan(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[1].value)
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[2].value)
                                        )
                                    )
                                )
                            );
                        }
                        break;
                    case E_LDMVGPRW:
                        {
                            il.AddInstruction(
                                il.Intrinsic(
                                    { 
                                        //RegisterOrFlag::Register(this->get_r_reg(instr->fields[0].value)) 
                                    }, // Outputs
                                    E_LDMVGPRW_INTRINSIC,
                                    {   
                                        il.Add(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value) 
                                            ),
                                            il.SignExtend(
                                                4,
                                                il.Const(
                                                    1,
                                                    instr->fields[1].value
                                                )
                                            )
                                        ),
                                        /*il.Register(4, this->get_r_reg(0)),
                                        il.Register(4, this->get_r_reg(3)),
                                        il.Register(4, this->get_r_reg(4)),
                                        il.Register(4, this->get_r_reg(5)),
                                        il.Register(4, this->get_r_reg(6)),
                                        il.Register(4, this->get_r_reg(7)),
                                        il.Register(4, this->get_r_reg(8)),
                                        il.Register(4, this->get_r_reg(9)),
                                        il.Register(4, this->get_r_reg(10)),
                                        il.Register(4, this->get_r_reg(11)),
                                        il.Register(4, this->get_r_reg(12))*/
                                    } // Inputs
                                )
                            );
                            /*
                                il.AddInstruction(
                                il.SetRegister(
                                    4,
                                    this->get_r_reg(0),
                                    il.Load(
                                        4,
                                        il.Add(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value)
                                            ),
                                            il.SignExtend(
                                                4,
                                                il.Const(
                                                    1,
                                                    instr->fields[1].value
                                                )
                                            )
                                        )
                                    )
                                )
                            );
                            int r = 3;
                            for (int i=1; i<11; i++) {
                                il.AddInstruction(
                                    il.SetRegister(
                                        4,
                                        this->get_r_reg(r),
                                        il.Load(
                                            4,
                                            il.Add(
                                                4,
                                                il.Register(
                                                    4,
                                                    this->get_r_reg(instr->fields[0].value)
                                                ),
                                                il.Add(
                                                    4,
                                                    il.Const(
                                                        4,
                                                        4 * i
                                                    ),
                                                    il.SignExtend(
                                                        4,
                                                        il.Const(
                                                            1,
                                                            instr->fields[1].value
                                                        )
                                                    )
                                                )
                                                
                                            )
                                        )
                                    )
                                );
                                r++;
                            }
                            */
                        }
                        break;
                    case E_STMVGPRW:
                        {
                            // It is actually pretier to use Intrinsic
                            il.AddInstruction(
                                il.Intrinsic(
                                    { 
                                        //RegisterOrFlag::Register(this->get_r_reg(instr->fields[0].value)) 
                                    }, // Outputs
                                    E_STMVGPRW_INTRINSIC,
                                    {   
                                        il.Add(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value) 
                                            ),
                                            il.SignExtend(
                                                4,
                                                il.Const(
                                                    1,
                                                    instr->fields[1].value
                                                )
                                            )
                                        ),
                                        /*il.Register(4, this->get_r_reg(0)),
                                        il.Register(4, this->get_r_reg(3)),
                                        il.Register(4, this->get_r_reg(4)),
                                        il.Register(4, this->get_r_reg(5)),
                                        il.Register(4, this->get_r_reg(6)),
                                        il.Register(4, this->get_r_reg(7)),
                                        il.Register(4, this->get_r_reg(8)),
                                        il.Register(4, this->get_r_reg(9)),
                                        il.Register(4, this->get_r_reg(10)),
                                        il.Register(4, this->get_r_reg(11)),
                                        il.Register(4, this->get_r_reg(12))*/
                                    } // Inputs
                                )
                            );
                            /*
                            il.AddInstruction(
                                il.Store(
                                    4,
                                    il.Add(
                                        4,
                                        il.Register(
                                            4,
                                            this->get_r_reg(instr->fields[0].value)
                                        ),
                                        il.SignExtend(
                                            4,
                                            il.Const(
                                                1,
                                                instr->fields[1].value
                                            )
                                        )
                                    ),
                                    il.Register(
                                        4,
                                        this->get_r_reg(0)
                                    )
                                )
                            );
                            int r = 3;
                            for (int i=1; i<11; i++) {
                                il.AddInstruction(
                                    il.Store(
                                        4,
                                        il.Add(
                                            4,
                                            il.Register(
                                                4,
                                                this->get_r_reg(instr->fields[0].value)
                                            ),
                                            il.Add(
                                                4,
                                                il.Const(
                                                    4,
                                                    4 * i
                                                ),
                                                il.SignExtend(
                                                    4,
                                                    il.Const(
                                                        1,
                                                        instr->fields[1].value
                                                    )
                                                )
                                            )
                                            
                                        ),
                                        il.Register(
                                            4,
                                            this->get_r_reg(r)
                                        )
                                    )
                                );
                                r++;
                            }*/
                        }
                        break;
                    case SE_ILLEGAL:
                        {
                            il.AddInstruction(il.Trap(0));
                        }
                        break;
                    default:
                        il.AddInstruction(il.Unimplemented());
                        break;
                    }
                }
                /*
                LogInfo("%s AT 0x%x: N: %d", instr_name, (uint32_t)addr,instr->n);
                LogInfo("%s OP[0] type: %d: value: %d", instr_name, instr->fields[0].type,instr->fields[0].value);
                LogInfo("%s OP[1] type: %d: value: %d", instr_name, instr->fields[1].type,instr->fields[1].value);
                LogInfo("%s OP[2] type: %d: value: %d", instr_name, instr->fields[2].type,instr->fields[2].value);
                */
                return true;
            } else {
                // These should be hadnled by PowerPC but are not
                // 011e6eb0 vaddsbs
                // Floating points
                // TODO wrteeX
                // TODO mfspr and friends
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
                            PPC_REG_MSR,
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
                            PPC_REG_MSR
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
            if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2) == 0 || strncmp(instr->name, "ef",2) == 0 || strncmp(instr->name, "ev",2) == 0) {
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
            if (strncmp(instr->name, "se_",3) == 0 || strncmp(instr->name, "e_", 2) == 0 || strncmp(instr->name, "ef",2) == 0 || strncmp(instr->name, "ev",2) == 0) {
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