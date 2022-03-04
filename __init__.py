from .arch import CoolVMArch
from .view import CoolVMView
from binaryninja import CallingConvention, Architecture

class COOLVMcc(CallingConvention):
    name = "coolvm_cc"
    int_arg_regs = ["r1"]


CoolVMArch.register()
cc = COOLVMcc(Architecture['coolvm'],'default')
Architecture['coolvm'].register_calling_convention(cc)
CoolVMView.register()