from bf import bf
from validator import *
from tekcap import *

class ip6ext(tekcap):
	fields = ('nexthdr', 'hdrlen')
	validator = (u8_validator, u8_validator)

	def __repr__(self):
		return chr(self.nexthdr) + chr(self.hdrlen)


class ip6hdr(tekcap):
	fields = ('traffic_cls', 'flow_lbl', 'payload_len', 'nexthdr', 'hop_limit', 
		'saddr', 'daddr')
	validator = (u8_validator, u20_validator, u16_validator, u8_validator, 
		u8_validator, ipv6_addr_validator, ipv6_addr_validator)
	version = property(lambda x: 6)
		
	def __str__(self):
		octet = bf()
		octet[4:8] = 6
		octet[0:4] = (self.traffic_cls & 0xf0) >> 4
		output = chr(octet)
		octet = bf()
		octet[4:8] = self.traffic_cls & 0xf
		octet[0:4] = (self.flow_lbl & 0xf0000) >> 16
		output = output + chr(octet) + ns_str(self.flow_lbl)
		output = output + ns_str(self.payload_len)
		output = output + chr(self.nexthdr) + chr(self.hop_limit)
		output = output + self.saddr
		output = output + self.daddr

		return output
		
