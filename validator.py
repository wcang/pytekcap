import socket
import types

def int_validator_factory(lower, upper):
	def func(value):
		if type(value) != types.IntType and type(value) != types.LongType:
			raise ValueError, value

		if value < lower or value > upper:
			raise ValueError, "Valid range is from %d to %d" % (lower, upper)
		return value
	return func

u8_validator = int_validator_factory(0, 2**8 - 1)
u20_validator = int_validator_factory(0, 2**20 - 1)
u16_validator = int_validator_factory(0, 2**16 - 1)
u4_validator = int_validator_factory(0, 2**4 - 1)
u13_validator = int_validator_factory(0, 2**13 - 1)
	
def ipv6_addr_validator(value):
	return socket.inet_pton(socket.AF_INET6, value)

def ipv4_addr_validator(value):
	return socket.inet_pton(socket.AF_INET, value)

def boolean_validator(value):
	if type(value) != types.BooleanType and type(value) != types.IntType:
		raise ValueError, "Boolean or (0|1) expected"
	
	if type(value) == types.IntType:
		if value != 0 and value != 1:
			raise ValueError, "Boolean or (0|1) expected"
	if value:
		return 1
	else:
		return 0
