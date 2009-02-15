def nl_str(value):
	return ns_str((value & 0xffff0000) >> 16) + ns_str(value)

def ns_str(value):
	return chr((value & 0xff00) >> 8) + chr((value & 0xff))

def nc_str(value):
	return chr(value & 0xff)

class tekcap:
	def __setattr__(self, attr, value):
		for index, field in enumerate(self.fields):
			if field == attr:
				self.__dict__[attr] = self.validator[index](value)
				break
		else:
			raise AttributeError, attr

	def __getattr__(self, attr):
		if attr not in self.fields:
			raise AttributeError, attr
		
		return self.__dict__[attr]

def join(*args):
	checking = []
	buf = ''
	prev_pkt = None
	for pkt in args:
		if hasattr(pkt, 'need_csum') and pkt.need_csum():
			checking.append((prev_pkt, pkt, len(buf)))
		buf = buf + str(pkt)
		prev_pkt = pkt

	for (prev_pkt, pkt, offset) in checking:
		buf = pkt.perform_checksum(prev_pkt, buf, offset)

	return buf
