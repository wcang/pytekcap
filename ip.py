from bf import bf
from validator import *
from tekcap import *

ihl_validator = int_validator_factory(5, 2**4 - 1)

#Taken from netinet/in.h
IPPROTO_IP = 0 		   # Dummy protocol for TCP
IPPROTO_HOPOPTS = 0	   # IPv6 Hop-by-Hop options.
IPPROTO_ICMP = 1	   # Internet Control Message Protocol.  
IPPROTO_IGMP = 2	   # Internet Group Management Protocol. 
IPPROTO_IPIP = 4	   # IPIP tunnels (older KA9Q tunnels use 94).  
IPPROTO_TCP = 6	   # Transmission Control Protocol.  
IPPROTO_EGP = 8	   # Exterior Gateway Protocol.  
IPPROTO_PUP = 12	   # PUP protocol.  
IPPROTO_UDP = 17	   # User Datagram Protocol.  
IPPROTO_IDP = 22	   # XNS IDP protocol.  
IPPROTO_TP = 29	   # SO Transport Protocol Class 4.  
IPPROTO_IPV6 = 41	# IPv6 header.  
IPPROTO_ROUTING = 43  	# IPv6 routing header.  
IPPROTO_FRAGMENT = 44 	# IPv6 fragmentation header.  
IPPROTO_RSVP = 46	   # Reservation Protocol.  
IPPROTO_GRE = 47	   # General Routing Encapsulation.  
IPPROTO_ESP = 50      	# encapsulating security payload.  
IPPROTO_AH = 51       	# authentication header.  
IPPROTO_ICMPV6 = 58   	# ICMPv6.  
IPPROTO_NONE = 59     	# IPv6 no next header.  
IPPROTO_DSTOPTS = 60  	# IPv6 destination options.  
IPPROTO_MTP = 92	   # Multicast Transport Protocol.  
IPPROTO_ENCAP = 98	   # Encapsulation Header.  
IPPROTO_PIM = 103	   # Protocol Independent Multicast.  
IPPROTO_COMP = 108	   # Compression Header Protocol.  
IPPROTO_SCTP = 132	   # Stream Control Transmission Protocol.  
IPPROTO_RAW = 255	   # Raw IP packets.  

class iphdr(tekcap):
	#flags not handled yet
	fields = ('ihl', 'tos', 'tot_len', 'id', 'df', 'mf', 'frag_off', 'ttl', 'protocol', 
		'checksum', 'saddr', 'daddr')
	validator = (ihl_validator, u8_validator, u16_validator, boolean_validator, 
		boolean_validator,u13_validator, u4_validator, u4_validator, 
		u16_validator, ipv4_addr_validator, ipv4_addr_validator)
	version = property(lambda x: 4)
	def __init__(self):
		self.__dict__['df'] = 0
		self.__dict__['mf'] = 0
		self.__dict__['ihl'] = 5
		self.__dict__['checksum'] = 0

	def __str__(self):
		octet = bf()
		octet[4:8] = 4
		octet[0:4] = self.ihl
		output = chr(octet) + chr(self.tos)
		output = output + ns_str(self.tot_len) + ns_str(self.id)
		octet = bf()
		
		if self.df:
			octet[6] = 1

		if self.mf:
			octet[5] = 1

		octet[0:5] = chr((self.frag_off & 0x1f00) >> 8)
		output = output + chr(octet) + nc_str(self.frag_off)
		output = output + chr(self.ttl) + chr(self.protocol)
		#FIXME checksum
		if self.checksum != 0:
			output = output + ns_chr(self.checksum)
		else:
			pass

		output = output + ns_str(0) 
		output = output + self.saddr + self.daddr
		#FIXME option and padding

		return output
