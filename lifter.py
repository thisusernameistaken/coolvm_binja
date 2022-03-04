from binaryninja import LowLevelILLabel, Architecture
from binaryninja.lowlevelil import LLIL_TEMP, ILRegister

def mov(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]
    op3_val = il.const(1,op_3)
    il_reg = f"r{op_1}"
    il.append(il.set_reg(1,il_reg,op3_val))
    return 4

def push(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    il_reg = il.reg(1,f"r{op_2}")
    il.append(il.push(1,il_reg))
    return 4

def pop(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    il_reg = f"r{op_1}"
    il.append(il.set_reg(1,il_reg,il.pop(1)))
    return 4

def f_print(data,addr,il):
    op_2 = data[2]
    op = il.reg(1,f"r{op_2}")
    il.append(il.intrinsic([],"print",[op]))
    return 4

def f_read(data,addr,il):
    op_1 = data[1]
    op = il.reg(1,f"r{op_1}")
    op2 = il.reg(1,f"r3")
    temp = LLIL_TEMP(il.temp_reg_count)
    temp_il = ILRegister(il.arch, temp)
    il.append(il.intrinsic([temp_il],"read",[]))
    il.append(il.set_reg(1,f"r{op_1}",il.reg(1,temp)))
    return 4

def f_xor(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    op_3_val = il.const(1,op_3)
    il_reg = il.reg(1,f"r{op_1}")
    xor = il.xor_expr(1,il_reg,op_3_val)
    il.append(il.set_reg(1,f"r{op_1}",xor))
    return 4

def f_exitie(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    il_reg_1 = il.reg(1,f"r{op_1}")
    il_reg_2 = il.reg(1,f"r{op_2}")
    cond = il.compare_not_equal(1,il_reg_1,il_reg_2)
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    il.append(il.if_expr(cond,t,f))
    il.mark_label(t)
    il.append(il.intrinsic([],"exit",[]))
    il.mark_label(f)
    return 4

def f_exit(data,addr,il):
    il.append(il.intrinsic([],"exit",[]))
    il.append(il.no_ret())
    return 4

def sub(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3]

    il_reg_1 = il.reg(1,f"r{op_1}")
    il_reg_2 = il.reg(1,f"r{op_2}")
    expr = il.sub(1,il_reg_2,il_reg_1)
    il.append(il.set_reg(1,"r4",expr))
    return 4

def jne(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3] + 4
    
    il_reg_1 = il.reg(1,f"r4")
    zero = il.const(1,0)
    cond = il.compare_not_equal(1,il_reg_1,zero)
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    il.append(il.if_expr(cond,t,f))
    il.mark_label(t)
    tmp = il.get_label_for_address(Architecture['coolvm'],addr+op_3)
    il.append(il.goto(tmp))
    il.mark_label(f)
    return 4

def jneb(data,addr,il):
    op_1 = data[1]
    op_2 = data[2]
    op_3 = data[3] - 4
    
    il_reg_1 = il.reg(1,f"r4")
    zero = il.const(1,0)
    cond = il.compare_not_equal(1,il_reg_1,zero)
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    il.append(il.if_expr(cond,t,f))
    il.mark_label(t)
    tmp = il.get_label_for_address(Architecture['coolvm'],addr-op_3)
    # il.append(il.jump(il.const_pointer(1,addr+4-op_3)))
    il.append(il.goto(tmp))
    il.mark_label(f)
    return 4

class CoolVMLifter:
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
        10 : f_exitie,
    }