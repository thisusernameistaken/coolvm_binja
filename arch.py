from binaryninja import (
    Architecture,
    Endianness,
    RegisterInfo,
    IntrinsicInfo,
    Type,
    InstructionInfo
)
from .disassembler import CoolVMDisassembler
from .lifter import CoolVMLifter

class CoolVMArch(Architecture):
    name = "coolvm"
    
    endianness = Endianness.BigEndian
    default_int_size = 1
    max_instr_size = 4
    instr_alignment = 4

    stack_pointer = "sp"

    regs = {}
    regs['sp'] = RegisterInfo("sp",1)
    regs['pc'] = RegisterInfo("pc",1)
    regs['exit'] = RegisterInfo("exit",1)
    for x in range(1,5):
        reg_name = f"r{x}"
        regs[reg_name] = RegisterInfo(reg_name,1)


    intrinsics = {
        "read": IntrinsicInfo([],[Type.char()]),
        "print": IntrinsicInfo([Type.char()],[]),
        "exit": IntrinsicInfo([],[]),
        "printStr": IntrinsicInfo([],[])
    }

    def __init__(self):
        super().__init__()
        self.disassembler = CoolVMDisassembler()
        self.lifter = CoolVMLifter()

    def get_instruction_info(self,data,addr):
        _, branch_conds = self.disassembler.disas(data,addr)
        instr_info = InstructionInfo(4)
        for branch_info in branch_conds:
            if branch_info.target is not None:
                instr_info.add_branch(branch_info.type,branch_info.target)
            else:
                instr_info.add_branch(branch_info.type)
        return instr_info

    def get_instruction_text(self,data,addr):
        tokens,_ = self.disassembler.disas(data,addr)
        return tokens,4

    def get_instruction_low_level_il(self,data,addr,il):
        self.lifter.lift(data,addr,il)
        return 4
