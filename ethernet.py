from validator import *
from tekcap import *

ETH_P_ALL = 0x0003
ETH_P_IPV6 = 0x86dd
ETH_P_IP = 0x0800

def ether_validator(value):
	output = ''
	for octet in value.split(':'):
		if len(octet) != 2:
			raise ValueError, "%s is not a valid Ethernet address" % value
		
		output = output + chr(int(octet, 16))

	if len(output) != 6:
		raise ValueError, "%s is not a valid Ethernet address" % value

	return output

class ethhdr(tekcap):
	fields = ('dest', 'source', 'type')
	validator = (ether_validator, ether_validator, u16_validator)

	def __repr__(self):
		return self.dest + self.source + ns_str(self.type)
