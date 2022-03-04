from binaryninja import InstructionTextToken, InstructionTextTokenType, BranchType

def mov(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_1 < 5:
        reg1 = f"r{op_1}"
    elif op_1 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"mov")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ', '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(op_3),value=op_3))
    return tokens,4,[]

def push(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_2 < 5:
        reg1 = f"r{op_2}"
    elif op_2 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"push")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    return tokens,4,[]    

def pop(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_1 < 5:
        reg1 = f"r{op_1}"
    elif op_1 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"pop")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    return tokens,4,[]    

def sub(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_1 < 5:
        reg1 = f"r{op_1}"
    elif op_1 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    if op_2 < 5:
        reg2 = f"r{op_2}"
    elif op_2 == 5:
        reg2 = "pc"
    else:
        reg2 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"sub")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ', '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
    return tokens,4,[]    

def jne(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    off = op_3 + 4
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"jne")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(addr+off),addr+off))
    return tokens,4,[(BranchType.TrueBranch,addr+off),(BranchType.FalseBranch,addr+4)]    

def jneb(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    reg1 = f"r{op_1}"
    reg2 = f"r{op_2}"
    off = op_3 - 4
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"jneb")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(addr-off),addr-off))
    return tokens,4,[(BranchType.TrueBranch,addr-off),(BranchType.FalseBranch,addr+4)]    

def f_print(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_2 < 5:
        reg1 = f"r{op_2}"
    elif op_2 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"print")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    return tokens,4,[]    

def f_read(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_1 < 5:
        reg1 = f"r{op_1}"
    elif op_1 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"read")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    return tokens,4,[]    

def f_exitie(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_1 < 5:
        reg1 = f"r{op_1}"
    elif op_1 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    if op_2 < 5:
        reg2 = f"r{op_2}"
    elif op_2 == 5:
        reg2 = "pc"
    else:
        reg2 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"exit_if_eq")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ', '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
    return tokens,4,[(BranchType.UnconditionalBranch,addr+4)]

def f_xor(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    if op_1 < 5:
        reg1 = f"r{op_1}"
    elif op_1 == 5:
        reg1 = "pc"
    else:
        reg1 = "sp"
    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"xor")]
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ', '))
    tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(op_3),value=op_3))
    return tokens,4,[]

def f_exit(data,addr):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"exit")]
    return tokens,4,[(BranchType.FunctionReturn,None)]    