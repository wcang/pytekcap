from tekcap import *
from validator import *
import ip
import binascii

class udphdr(tekcap):
	fields = ('source', 'dest', 'len', 'check')
	validator = (u16_validator, u16_validator, u16_validator, u16_validator)

	def need_csum(self):
		return self.check == 0
	
	def __init__(self):
		self.__dict__['check'] = 0
	
	def __str__(self):
		return ns_str(self.source) + ns_str(self.dest) + ns_str(self.len) + ns_str(self.check)

	def perform_checksum(self, hdr, buf, offset):
		'''
		perform_checksum(ip, buf, offset) -> str

		hdr -> IPv4 or IPv6 header
		buf -> completely computed buffer
		offset -> offset to buf that point to starts with udp header
		'''
		csum = 0

		if hdr.version == 6:
			temp = hdr.saddr
			for i in range(8):
				csum = csum + (ord(temp[i * 2]) << 8) + ord(temp[i * 2 + 1])
		
			temp = hdr.daddr
			for i in range(8):
				csum = csum + (ord(temp[i * 2]) << 8) + ord(temp[i * 2 + 1])

			temp = nl_str(self.len)
			csum = csum + (ord(temp[0]) << 8) + ord(temp[1])
			csum = csum + (ord(temp[2]) << 8) + ord(temp[3])
			temp = nl_str(ip.IPPROTO_UDP)
			csum = csum + (ord(temp[0]) << 8) + ord(temp[1])
			csum = csum + (ord(temp[2]) << 8) + ord(temp[3])
		elif hdr.version == 4:
			temp = hdr.saddr
			csum = csum + (ord(temp[0]) << 8) + ord(temp[1])
			csum = csum + (ord(temp[2]) << 8) + ord(temp[3])
			temp = hdr.daddr
			csum = csum + (ord(temp[0]) << 8) + ord(temp[1])
			csum = csum + (ord(temp[2]) << 8) + ord(temp[3])
			temp = ns_str(ip.IPPROTO_UDP)
			csum = csum + (ord(temp[0]) << 8) + ord(temp[1])
			temp = ns_str(self.len)
			csum = csum + (ord(temp[0]) << 8) + ord(temp[1])
		else:
			raise ValueError, "Invalid IP version"

		udp_len = len(buf) - offset
		index = offset
		
		while udp_len > 1:
			csum = csum + (ord(buf[index]) << 8) + ord(buf[index + 1])
			index = index + 2
			udp_len = udp_len - 2

		if udp_len:
			csum = csum + (ord(buf[-1]) << 8)
	
		while (csum >> 16) != 0:
			csum = (csum & 0xffff) + (csum >> 16)
	
		if csum == 0:
			csum = 0xffff

		csum = ~csum	
		return buf[:offset+6] + ns_str(csum) + buf[offset+8:]
