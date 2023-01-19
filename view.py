from binaryninja import (
    Architecture,
    BinaryView,
    Endianness,
    SegmentFlag,
    SectionSemantics
)

class CoolVMLoader(BinaryView):
    name = "coolvm"
    long_name = "coolvm loader"

    def __init__(self,data):
        BinaryView.__init__(self,file_metadata=data.file,parent_view=data)
        self.raw = data
    
    @classmethod
    def is_valid_for_data(cls,data):
	    return data.read(0,4) == b"COOL"

    def perform_get_default_endianness(self):
	    return Endianness.BigEndian

    def init(self):
        self.platform = Architecture['coolvm'].standalone_platform
        self.arch = Architecture['coolvm']

        end = len(self.raw)
        if (b"_"*0x10) in self.raw[::]:
	        end = self.raw[::].index(b"_"*0x10)

        self.add_auto_segment(0x1000,end-4,4,end-4,
            SegmentFlag.SegmentReadable|
            SegmentFlag.SegmentContainsCode|
            SegmentFlag.SegmentExecutable)
        self.add_auto_section(".code",0x1000,end-4,SectionSemantics.ReadOnlyCodeSectionSemantics)
        return True