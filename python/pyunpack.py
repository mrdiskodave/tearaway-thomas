import struct
import array
import sys

class SourceFile:
	def __init__(self, mem, shifter=128):
		self.mem = array.array('B', mem)
		self.shiftreg = shifter
		self.pos = len(mem)

	def _peekm(self):
		self.pos -= 1
		return self.mem[self.pos]

	def _getbit(self):
		if self.shiftreg==128:
			a = s = self._peekm()
			print "IN : {0:08x} {1:02x} {1:08b} bitstream data".format(self.pos, a)
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
	def peekm(self):
		a = self._peekm()
		print "IN : {0:08x} {1:02x} {2:8s} unpacked data".format(self.pos, a, '')
		return a

	def getbit(self):
		answer = self._getbit()
		#print "bit:{0}".format(answer)
		return answer

	def getbits(self, count):
		answer = 0
		for _ in range(count):
			a = self._getbit()
			answer <<= 1
			answer |= a
		return answer

class DestinationFile:
	def __init__(self, size, expect):
		self.a = array.array('B', chr(0)*size)
		self.pos = size
		self.expect = array.array('B', expect) if expect else None
		
	def isend(self, g):
		self.pos -= 1
		self.a[self.pos] = g
		if self.expect:
			x = self.expect[self.pos]
			if x!=g:
				msg = "Got {0:02x} but expected {1:02x} at {2:08x}".format(g, x, self.pos)
				assert False, msg
			else:
				print "Correct!"

		
	def send(self, x):
		print "OUT: {0:08x} {0:02x}".format(self.pos, x)
		self.isend(x)

	def copy(self, length, offset):
		print "OUT: {0:08x} +{1:x}*{2:x}".format(self.pos, offset, length)
		for _ in xrange(length):
			self.isend(self.a[self.pos+offset])

	def done(self):
		return self.pos==0

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

#ModeChoice
#dc.l    41000       8
#dc.l    20000       7
#dc.l    9500        6
#dc.l    6000        5
#dc.l    3200        4
#dc.l    1700        3
#dc.l    770     2
#dc.l    360     1
#dc.l    0       0


UNPACKED_MODESTORE = (
		( 0x00, 0x00, 0x00, 0x00 ),				#0	0
		( 0x01, 0x02, 0x02, 0x03 ),				#4	1
		( 0x03, 0x04, 0x06, 0x0d ),				#8	2
	)

OFFSET_MODESTORE = (
	# 0
	(
		( 0x04, 0x04, 0x04, 0x04 ),
		( 0x04, 0x04, 0x04, 0x04 ),
		( 0x05, 0x05, 0x05, 0x05 ),
	),

	# 1
	(
		( 0x04, 0x05, 0x06, 0x06 ),
		( 0x05, 0x05, 0x05, 0x05 ),
		( 0x06, 0x06, 0x05, 0x05 ),
	),

	# 2
	(
		( 0x04, 0x05, 0x06, 0x06 ),
		( 0x06, 0x06, 0x06, 0x06 ),
		( 0x07, 0x07, 0x07, 0x07 ),
	),

	(
		( 0x04, 0x05, 0x06, 0x07 ),
		( 0x06, 0x06, 0x07, 0x07 ),
		( 0x07, 0x08, 0x08, 0x08 ),
	),

	# 4
	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x07, 0x08, 0x08 ),
		( 0x07, 0x08, 0x09, 0x09 ),
	),

	# 5
	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x08, 0x09 ),
		( 0x07, 0x09, 0x0a, 0x0a ),
	),

	# 6
	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x08, 0x09 ),
		( 0x07, 0x09, 0x0b, 0x0b ),
	),

	# 7
	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x09, 0x09 ),
		( 0x07, 0x0a, 0x0b, 0x0c ),
	),

	# 8
	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x09, 0x0a ),
		( 0x07, 0x0a, 0x0c, 0x0d ),
	),

)

#for m in OFFSET_MODESTORE:



#for x in range(5, -1, -1):
#	print "( {0}, {1}, {2} ), # ".format(LenBase[x], LenRead[x], LenMode[x])
#sys.exit(1)

MAGIC_SIZE = 4
HEAD_SIZE = 18

def read_mode_store(m, modestore, localmode, reason):
	xs = modestore[0][localmode]+1
	xm = modestore[1][localmode]+1
	xl = modestore[2][localmode]+1
	if m.getbit():
		answer = m.getbits(xs)
	else:
		if m.getbit():
			# MedLongMS
			answer = m.getbits(xm)+(1<<xs)
		else:
			# LongMS
			answer = m.getbits(xl)+(1<<xs)+(1<<xm)
	return answer

data = load_file("wfnsh.packed.bin")
#data = load_file("bigTT.lbm")
assert data[:MAGIC_SIZE]=='DHp2'
fullength, packedlength, unpacked, packmode, shifter  = struct.unpack('>LLLBB', data[MAGIC_SIZE:HEAD_SIZE])
assert packedlength==len(data)
print "header", packmode, hex(shifter)

expect = load_file("wfnsh.unpacked.bin")
result = DestinationFile(fullength, expect)

restore_from_the_end = min(packedlength, HEAD_SIZE)

data = data[-restore_from_the_end:]+data[HEAD_SIZE:-restore_from_the_end]

m = SourceFile(data, shifter)

for _ in xrange(unpacked):
	result.send(m.peekm())


offset_modestore = OFFSET_MODESTORE[packmode]

base_read_mode = (
	(  2, 0, 0 ), # 0: 1               length 2
	(  3, 0, 1 ), # 1: 01              length 3
	(  4, 0, 2 ), # 2: 001             length 4
	(  5, 0, 3 ), # 3: 0001            length 5
	(  6, 3, 3 ), # 4: 00001xxx        length 6-13   inclusive
	( 14, 8, 3 ), # 5: 00000xxxxxxxx   length 14-269 inclusive (n.b. no '1' on this one)
)

while not result.done():
	x = 0
	while x!=5 and m.getbit()==0:
		x += 1
	base, read, localmode = base_read_mode[x]
	print "basereadmode", base, read, localmode

	length = m.getbits(read)
	length += base

	offset = read_mode_store(m, offset_modestore, localmode, "offset")
	unpacked = read_mode_store(m, UNPACKED_MODESTORE, localmode, "unpacked length")
	#print "need to read {0} unpacked bytes".format(unpacked)


	result.copy(length, offset)

	for _ in xrange(unpacked):
		result.send(m.peekm())

with open("answer.lbm", 'w') as f:
	result.a.tofile(f)


THE_END = """

>>> ''.join([ hex(ord(c))[2:] for c in "DHp2" ])
'44487032'
>>> 0x44487032
1145598002
>>>


  606  ilbmtoppm < answer.lbm | ppmtogif >answer.gif


"""

