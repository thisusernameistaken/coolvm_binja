from binaryninja import (
    LowLevelILLabel,
)
from .disassembler import Instruction

class CoolVMLifter():

    def __init__(self):
        self.instructions = {
            0: ["mov",self.mov],
            1: ["push",self.push],
            2: ["pop",self.pop],
            3: ["sub",self.sub],
            4: ["jnz",self.jnz],
            5: ["jnzb",self.jnzb],
            6: ["print",self.print],
            7: ["read",self.read],
            8: ["exit",self.exit],
            9: ["xor",self.xor],
            10:["ene",self.ene],
        }

    def lift(self,data,addr,il):
        instr = Instruction(data)
        mnem, func = self.instructions[instr.opcode]
        return func(instr,addr,il)

    def mov(self,instr,addr,il):
        op3_const = il.const(1,instr.op3)
        il_mov = il.set_reg(1,instr.op1,op3_const)
        il.append(il_mov)

    def push(self,instr,addr,il):
        il_reg = il.reg(1,instr.op2)
        il.append(il.push(1,il_reg))

    def pop(self,instr,addr,il):
        il_pop = il.pop(1)
        il_set = il.set_reg(1,instr.op1,il_pop)
        il.append(il_set)

    def sub(self,instr,addr,il):
        il_op1 = il.reg(1,instr.op1)
        il_op2 = il.reg(1,instr.op2)
        il_sub = il.sub(1,il_op2,il_op1)
        il.append(il.set_reg(1,"r4",il_sub))
    
    def jnz(self,instr,addr,il):
        il_reg_zero = il.reg(1,"r4")
        il_zero = il.const(1,0)
        target = il.const(2,addr+instr.op3)
        cond = il.compare_not_equal(1,il_reg_zero,il_zero)
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(cond,t,f))
        il.mark_label(t)
        il.append(il.jump(target))
        il.mark_label(f)

    def jnzb(self,instr,addr,il):
        il_reg_zero = il.reg(1,"r4")
        il_zero = il.const(1,0)
        target = il.const_pointer(1,addr-instr.op3)
        cond = il.compare_not_equal(1,il_reg_zero,il_zero)
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(cond,t,f))
        il.mark_label(t)
        il.append(il.jump(target))
        il.mark_label(f)

    def print(self,instr,addr,il):
        il_op = il.reg(1,instr.op2)
        il.append(il.intrinsic([],"print",[il_op]))

    def read(self,instr,addr,il):
        il_op = il.reg(1,instr.op1)
        il.append(il.intrinsic([],"read",[il_op]))

    def exit(self,instr,addr,il):
        il.append(il.intrinsic([],"exit",[]))
        il.append(il.no_ret())

    def xor(self,instr,addr,il):
        il_reg = il.reg(1,instr.op1)
        op3_const = il.const(1,instr.op3)
        il_xor = il.xor_expr(1,il_reg,op3_const)
        il_expr= il.set_reg(1,instr.op1,il_xor)
        il.append(il_expr)

    def ene(self,instr,addr,il):
        il_op1 = il.reg(1,instr.op1)
        il_op2 = il.reg(1,instr.op2)
        cond = il.compare_not_equal(1,il_op1,il_op2)
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(cond,t,f))
        il.mark_label(t)
        il.append(il.intrinsic([],"exit",[]))
        il.mark_label(f)
    