
from binaryninja import (
    InstructionTextToken,
    InstructionTextTokenType,
    BranchType
)

class BranchInfo:
    def __init__(self,_type,target=None):
        self.type = _type
        self.target = target

class Instruction():
    def __init__(self,data):
        self.opcode = data[0]
        self.op1 = self.op2 = self.op3 = None
        for i,op in enumerate(["self.op1","self.op2"]):
            if data[i+1] < 5:
                exec(op + '= f"r{data[i+1]}"')
            elif data[i+1] == 5:      
                exec(op + '= "pc"')
            elif data[i+1] == 6:      
                exec(op + '= "sp"')
            else:
                exec(op + '= "BAD"')
        self.op3 = data[3]

class CoolVMDisassembler():

    def __init__(self):
        self.instructions = {
            0: ["mov",self.reg_imm],
            1: ["push",self.reg2],
            2: ["pop",self.reg1],
            3: ["sub",self.two_reg],
            4: ["jnz",self.jnz],
            5: ["jnzb",self.jnzb],
            6: ["print",self.reg2],
            7: ["read",self.reg1],
            8: ["exit",self.exit],
            9: ["xor",self.reg_imm],
            10:["ene",self.ene],
        }

    def disas(self,data,addr):
        instr = Instruction(data)
        mnem, func = self.instructions[instr.opcode]
        return func(mnem,instr,addr)

    def reg_imm(self,mnem,instr,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem+" ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(instr.op3),instr.op3))
        return tokens,[]

    def reg1(self,mnem,instr,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem+" ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op1))
        return tokens,[]

    def reg2(self,mnem,instr,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem+" ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op2))
        return tokens,[]
    
    def two_reg(self,mnem,instr,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem+" ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op2))
        return tokens,[]

    def jnz(self,mnem,instr,addr):
        target = instr.op3 + addr 
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem+" ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken,hex(target),target))

        true_branch = BranchInfo(BranchType.TrueBranch,target)
        false_branch = BranchInfo(BranchType.FalseBranch,addr +4)
        return tokens,[true_branch,false_branch]

    def jnzb(self,mnem,instr,addr):
        target = addr - instr.op3 
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem+" ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,instr.op1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken,hex(target),target))

        true_branch = BranchInfo(BranchType.TrueBranch,target)
        false_branch = BranchInfo(BranchType.FalseBranch,addr+4)
        return tokens,[true_branch,false_branch]

    def exit(self,mnem,instr,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,mnem)]
        exit_branch = BranchInfo(BranchType.FunctionReturn)
        return tokens,[exit_branch]

    def ene(self,mnem,instr,addr):
        tokens,_ = self.two_reg(mnem,instr,addr)
        exit_branch = BranchInfo(BranchType.TrueBranch,addr+4)
        return tokens,[exit_branch]
