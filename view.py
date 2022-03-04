from binaryninja import BinaryView, SegmentFlag, SectionSemantics, Architecture

class CoolVMView(BinaryView):
    name = "coolvm"
    long_name = "cool vm loader"

    def __init__(self,data):
        BinaryView.__init__(self,file_metadata=data.file,parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls,data):
        return data.read(0,4) == b"COOL"

    def init(self):
        self.platform = Architecture['coolvm'].standalone_platform
        self.arch = Architecture['coolvm']

        self.entry_addr = 0x0
        self.add_entry_point(self.entry_addr)
        self.add_auto_segment(0,len(self)-4,0x4,len(self)-4,SegmentFlag.SegmentContainsCode|SegmentFlag.SegmentExecutable|SegmentFlag.SegmentReadable)
        self.add_auto_section(".code",0,len(self)-4,SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_function(self.entry_addr)
        
        return True