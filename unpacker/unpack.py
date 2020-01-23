#
# Unpacker module for DHp2
#

import struct
import array

# ---------------------------------------------------------------------------
# CONSTANTS

# 0 - 8 used for reading the offset based on pack_mode
OFFSET_MODESTORES = (
	#      S   M   L    << Small (0), Medium (01) or Large (00) reach : column selection based on the bits that read_modestore reads
	( # 0
		(  5,  5,  6 ), # V row is chosen based on 'kind'
		(  5,  5,  6 ), # V
		(  5,  5,  6 ),
		(  5,  5,  6 ),
	),
	( # 1
		(  5,  6,  7 ),
		(  6,  6,  7 ),
		(  7,  6,  6 ),	# ?!
		(  7,  6,  6 ), # !?
	),
	( # 2
		(  5,  7,  8 ),
		(  6,  7,  8 ),
		(  7,  7,  8 ),
		(  7,  7,  8 ),
	),
	( # 3
		(  5,  7,  8 ),
		(  6,  7,  9 ),
		(  7,  8,  9 ),
		(  8,  8,  9 ),
	),
	( # 4
		(  6,  7,  8 ),
		(  7,  8,  9 ),
		(  7,  9, 10 ),
		(  8,  9, 10 ),
	),
	( # 5
		(  6,  7,  8 ),
		(  7,  9, 10 ),
		(  7,  9, 11 ),
		(  8, 10, 11 ),
	),
	( # 6
		(  6,  7,  8 ),
		(  7,  9, 10 ),
		(  7,  9, 12 ),
		(  8, 10, 12 ),
	),
	( # 7
		(  6,  7,  8 ),
		(  7,  9, 11 ),
		(  7, 10, 12 ),
		(  8, 10, 13 ),
	),
	( # 8
		(  6,  7,  8 ),
		(  7,  9, 11 ),
		(  7, 10, 13 ),
		(  8, 11, 14 ),
	),
)

# used for reading the length of unpacked data
UNPACKED_MODESTORE = (
	#  S   M   L    << Small (0), Medium (01) or Large (00) reach : column selection based on the bits that read_modestore reads
	(  1,  2,  4 ), # V row is chosen based on 'kind'
	(  1,  3,  5 ), # V
	(  1,  3,  7 ),
	(  1,  4, 14 ),
)

COMPRESSION_TYPES = (
	#  Base Read Kind:
	#  * base is the minimum length of the pattern (we're definately copying that many bytes)
	#  * read is the number of bits to read that might extend the base length of the pattern
	#  * kind is used to select a row from the modestore
	#  B  R  K
	(  2, 0, 0 ), # 0: 1               length 2
	(  3, 0, 1 ), # 1: 01              length 3
	(  4, 0, 2 ), # 2: 001             length 4
	(  5, 0, 3 ), # 3: 0001            length 5
	(  6, 3, 3 ), # 4: 00001xxx        length 6-13   inclusive
	( 14, 8, 3 ), # 5: 00000xxxxxxxx   length 14-269 inclusive (n.b. no '1' on this one)
)
MAXIMUM_COMPRESSION_TYPE = len(COMPRESSION_TYPES)-1

HEAD_SIZE = 18
MAGIC = 0x44487032 # 'DHp2'

# ---------------------------------------------------------------------------
# CLASSES

class SourceFile:
	def __init__(self, mem, pos, shifter=128):
		self.mem = mem
		self.pos = pos
		self.shiftreg = shifter

	def _read(self):
		self.pos -= 1
		return self.mem[self.pos]

	def _getBit(self):
		if self.shiftreg==128:
			a = s = self._read()
			if verbose: print "IN : {0:08x} {1:02x} {1:08b} bitstream data".format(self.pos, a)
			s &= 127
			s <<= 1
			s |= 1
		else:
			a = s = self.shiftreg
			s &= 127
			s <<= 1
		self.shiftreg = s
		return a >> 7

	# public methods:
	def getByte(self):
		a = self._read()
		if verbose: print "IN : {0:08x} {1:02x} {2:8s} unpacked data".format(self.pos, a, '')
		return a

	def getBit(self):
		answer = self._getBit()
		#print "bit:{0}".format(answer)
		return answer

	def getBits(self, count):
		answer = 0
		for _ in range(count):
			a = self._getBit()
			answer <<= 1
			answer |= a
		return answer

class DestinationFile:
	def __init__(self, mem, expect):
		self.mem = mem
		self.pos = len(mem)
		self.expect = expect
		
	def _write(self, data):
		self.pos -= 1
		self.mem[self.pos] = data
		if self.expect:
			expected = self.expect[self.pos]
			if expected!=data:
				msg = "Got {0:02x} but expected {1:02x} at {2:08x}".format(data, expected, self.pos)
				assert False, msg

	def send(self, x):
		if verbose: print "OUT: {0:08x} {0:02x}".format(self.pos, x)
		self._write(x)

	def copy(self, length, offset):
		if verbose: print "OUT: {0:08x} +{1:x}*{2:x}".format(self.pos, offset, length)
		for _ in xrange(length):
			self._write(self.mem[self.pos+offset])

	def done(self):
		return self.pos==0

# ---------------------------------------------------------------------------

def get_unpacked_size(data):
	"""
		Discover the unpacked length of a DHp2 file.
		Returns None if it isn't DHp2 or the answer.
	"""
	if len(data)<HEAD_SIZE: return None
	magic, full_length = struct.unpack('>LL', data[:8])
	if magic != MAGIC: return None
	return full_length

def unpack(data, expect=None):
	"""
		Decompress a DHp2 file.
		Returns the unpack output.
	"""
	def copy(src, dest, amount):
		for _ in xrange(unpacked):
			dest.send(src.getByte())

	def read_modestore(src, modestore, kind):
		s, m, l = modestore[kind]
		if src.getBit():
			# small
			answer = src.getBits(s)
		else:
			if src.getBit():
				# medium (allowing that we didn't use small)
				answer = src.getBits(m)+(1<<s)
			else:
				# large (allowing that we didn't use small or medium)
				answer = src.getBits(l)+(1<<s)+(1<<m)
		return answer

	# read the header
	magic, full_length, packed_length, unpacked, pack_mode, shifter  = struct.unpack('>LLLLBB', data[:HEAD_SIZE])
	assert magic == MAGIC
	data_length = len(data)

	# the header was added by moving the bytes under it to the end
	# so now we reverse this process
	# (this allows for unpacking in-place)
	restore_from_the_end = min(packed_length, HEAD_SIZE)
	for x in range(restore_from_the_end):
		data[x] = data[packed_length-restore_from_the_end+x]
	data_length -= restore_from_the_end

	# grow the array to accomodate the fully unpacked file
	while len(data) < full_length:
		data.append(0)

	# set up our src and dest classes (addressing the same data array)
	src = SourceFile(data, data_length, shifter)
	dest = DestinationFile(data, expect)

	offset_modestore = OFFSET_MODESTORES[pack_mode]

	copy(src, dest, unpacked)
	while not dest.done():
		x = 0
		while x!=MAXIMUM_COMPRESSION_TYPE and src.getBit()==0:
			x += 1
		base, read, kind = COMPRESSION_TYPES[x]

		length = base + src.getBits(read)
		offset = read_modestore(src, offset_modestore, kind)
		unpacked = read_modestore(src, UNPACKED_MODESTORE, kind)

		dest.copy(length, offset)
		copy(src, dest, unpacked)

	return data			# the same 'data' object we were given unpacked in place

# ---------------------------------------------------------------------------
# TESTING


if __name__ == "__main__":
	import os
	import sys
	import getopt

	def load_file(name):
		with open(name, 'r') as f:
			return array.array('B', f.read())

	def save_file(name, data):
		with open(name, 'w') as f:
			data.tofile(f)

	options, args = getopt.getopt(sys.argv[1:], 'vt')
	options = dict(options)
	verbose = '-v' in options
	run_test = '-t' in options

	if run_test:
		# self test
		print "=== SELF TEST"
		our_path = os.path.dirname(__file__)
		data = load_file(os.path.join(our_path, "wfnsh.packed.bin"))
		expect = load_file(os.path.join(our_path, "wfnsh.unpacked.bin"))
		unpack(data, expect)

	# action
	print "=== PROCESSING"
	for filename in args:
		print "=== Processing {0}".format(filename)
		data = load_file(filename)
		if get_unpacked_size(data) is None:
			print "Not packed"
		else:
			print "Unpacking"
			data = unpack(data)
			print "Saving "+filename
			save_file(filename, data)

