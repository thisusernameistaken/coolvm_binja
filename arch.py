from binaryninja import Architecture, Type, RegisterInfo, IntrinsicInput, IntrinsicInfo, InstructionInfo
from .dissasmbly import *
from .lifter import CoolVMLifter

class CoolVMArch(Architecture):
    name = "coolvm"

    default_int_size = 1
    max_instr_length = 4
    instr_alignment = 4

    """
    r1-r3
    zero_flag
    pc
    stack
    """
    regs = {
        "sp": RegisterInfo("sp",1),
        "pc": RegisterInfo("pc",1),
    }

    for x in range(1,5):
        regs[f"r{x}"] = RegisterInfo(f"r{x}",1)

    stack_pointer = "sp"

    opcodes = {
        0 : mov,
        1 : push,
        2 : pop,
        3 : sub,
        4 : jne,
        5 : jneb,
        6 : f_print,
        7 : f_read,
        8 : f_exit,
        9 : f_xor,
        10 : f_exitie
    }

    intrinsics = {
        "read": IntrinsicInfo([Type.char()],[Type.char()]),
        "print": IntrinsicInfo([IntrinsicInput(Type.char())],[]),
        "exit": IntrinsicInfo([],[])
    }

    def __init__(self):
        super().__init__()

    def get_instruction_info(self,data,addr):
        opcode = data[0]
        try:
            tokens,length,cond = CoolVMArch.opcodes[opcode](data,addr)
            result = InstructionInfo()
            result.length = length
            for c in cond:
                if c[1] is not None:
                    result.add_branch(c[0],c[1])
                else:
                    result.add_branch(c[0])
            return result
        except KeyError:
            pass

    def get_instruction_text(self,data,addr):
        try:
            opcode = data[0]
            tokens,length,cond = CoolVMArch.opcodes[opcode](data,addr)
            return tokens,length
        except KeyError:
            pass

    def get_instruction_low_level_il(self,data,addr,il):
        try:
            opcode = data[0]
            return CoolVMLifter.opcodes[opcode](data,addr,il)
        except KeyError:
            pass
