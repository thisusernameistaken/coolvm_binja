from binaryninja import (
    Workflow,
    Activity,
    Function,
    core,
    MediumLevelILOperation,
    ExpressionIndex,
    SegmentFlag,
    SectionSemantics,
    MediumLevelILFunction
)

STRING_BASE = 0xf000
def outline_prints(analysis_context):
    global STRING_BASE

    function = Function(handle=core.BNAnalysisContextGetFunction(analysis_context))
    bv = function.view
    last_index = function.mlil[-1].instr_index
    curr_index = 0
    
    while curr_index < last_index:
        mlil_instr = function.mlil[curr_index]
        if mlil_instr.operation == MediumLevelILOperation.MLIL_INTRINSIC and mlil_instr.intrinsic.name == 'print':
            start = index = curr_index
            end = None
            printed_string = b""
            while end is None:
                mlil = function.mlil[index]
                if mlil.operation != MediumLevelILOperation.MLIL_INTRINSIC:
                    end = index
                    break
                elif mlil.operation == MediumLevelILOperation.MLIL_INTRINSIC and mlil.intrinsic.name != 'print':
                    end = index
                    break
                else:
                    printed_string += bytes([mlil.params[0].constant])
                    mlil_nop = function.mlil.expr(MediumLevelILOperation.MLIL_NOP,0)
                    function.mlil.replace_expr(mlil,mlil_nop)
                    index += 1
            print(f"Printed string from {start} to {end} at {hex(mlil.address)}: '{printed_string}'")
            string_addr = STRING_BASE
            for ascii_string in bv.strings:
                if printed_string.decode() == ascii_string.value:
                    string_addr = ascii_string.start
                    break

            mlil_const_ptr = function.mlil.expr(MediumLevelILOperation.MLIL_CONST_PTR, ExpressionIndex(string_addr),size=4)
            call_param = function.mlil.expr(MediumLevelILOperation.MLIL_CALL_PARAM,2,function.mlil.add_operand_list([mlil_const_ptr]))
            mlil_intrinsic = function.mlil.expr(MediumLevelILOperation.MLIL_INTRINSIC,0,0,3,1,call_param-1)
            function.mlil.replace_expr(function.mlil[index-1],mlil_intrinsic)
            curr_index = end 
            # add segment
            raw_bv = bv.file.raw
            printed_string += b"\x00"
            if printed_string not in raw_bv[::]:
                if (b"_"*0x10) not in raw_bv[::]:
                    raw_bv.write(raw_bv.length,b"_"*0x10)
                string_data_offset = raw_bv.length
                raw_bv.write(string_data_offset,printed_string)
            else:
                string_data_offset = raw_bv[::].index(printed_string)

            if STRING_BASE == string_addr:
                bv.add_auto_segment(STRING_BASE,len(printed_string),string_data_offset,len(printed_string),SegmentFlag.SegmentContainsData|SegmentFlag.SegmentReadable)
                bv.add_auto_section(f".string_{hex(mlil.address)[2:]}",STRING_BASE,len(printed_string),SectionSemantics.ReadOnlyDataSectionSemantics)
                STRING_BASE += len(printed_string)
        else:
            curr_index += 1
    function.mlil.generate_ssa_form()

CoolVMPrintStrWf = Workflow().clone("CoolVMprintStrWorkflow")
CoolVMPrintStrWf.register_activity(Activity("CoolVMprintStr",action=outline_prints))
CoolVMPrintStrWf.insert('core.function.analyzeTailCalls',['CoolVMprintStr'])
