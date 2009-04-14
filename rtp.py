from bf import bf
from tekcap import *
from validator import *

class rtphdr(tekcap):
	fields = ('pad', 'ext', 'mark', 'pt', 'sn', 'ts', 'ssrc', 'csrc')
	validator = (boolean_validator, boolean_validator, boolean_validator,
		u7_validator, u16_validator, u32_validator, u32_validator)

	def __init__(self):
		self.__dict__['pad'] = 0
		self.__dict__['ext'] = 0
		self.__dict__['mark'] = 0
		self.__dict__['csrc'] = []
				
	def __str__(self):
		octet = bf()
		octet[6:8] = 2
		octet[5] = self.pad
		octet[4] = self.ext
		
		if len(self.csrc) > 16:
			raise Exception('CSRC count is %d. Exceeds 16' % len(self.csrc))

		octet[0:4] = len(self.csrc)
		output = chr(octet)
		octet = bf()
		octet[7] = self.mark
		octet[0:7] = self.pt
		output += chr(octet) + ns_str(self.sn)
		output += nl_str(self.ts) + nl_str(self.ssrc)

		for csrc in self.csrc:
			output += nl_str(u32_validator(csrc))
		
		return output
