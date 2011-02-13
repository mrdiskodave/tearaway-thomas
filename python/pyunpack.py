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

MODESTORES = (
	( # 0
		(  5,  5,  6 ),
		(  5,  5,  6 ),
		(  5,  5,  6 ),
		(  5,  5,  6 ),
	),
	( # 1
		(  5,  6,  7 ),
		(  6,  6,  7 ),
		(  7,  6,  6 ),
		(  7,  6,  6 ),
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
	( # 9
		(  1,  2,  4 ),
		(  1,  3,  5 ),
		(  1,  3,  7 ),
		(  1,  4, 14 ),
	),
)

#for z, ms in enumerate(MODESTORES):
#	print "( #", str(z)
#	for y in range(0, 4):
#		line = ', '.join([ str(ms[x][y]).rjust(2) for x in range(0, 3) ])
#		print "\t( "+line+" ),"
#	print "),"
#sys.exit(1)

base_read_mode = (
	(  2, 0, 0 ), # 0: 1               length 2
	(  3, 0, 1 ), # 1: 01              length 3
	(  4, 0, 2 ), # 2: 001             length 4
	(  5, 0, 3 ), # 3: 0001            length 5
	(  6, 3, 3 ), # 4: 00001xxx        length 6-13   inclusive
	( 14, 8, 3 ), # 5: 00000xxxxxxxx   length 14-269 inclusive (n.b. no '1' on this one)
)

MAGIC_SIZE = 4
HEAD_SIZE = 18

def read_mode_store(src, modestore, mode, reason):
	xs = modestore[mode][0]
	xm = modestore[mode][1]
	xl = modestore[mode][2]
	if src.getbit():
		answer = src.getbits(xs)
	else:
		if src.getbit():
			answer = src.getbits(xm)+(1<<xs)
		else:
			answer = src.getbits(xl)+(1<<xs)+(1<<xm)
	return answer

data = load_file("wfnsh.packed.bin")
#data = load_file("bigTT.lbm")

# check the magic number
assert data[:MAGIC_SIZE]=='DHp2'

# read the header
fullength, packedlength, unpacked, mode_store_choice, shifter  = struct.unpack('>LLLBB', data[MAGIC_SIZE:HEAD_SIZE])
assert packedlength==len(data)

# set up the destination buffer
expect = load_file("wfnsh.unpacked.bin")
dest = DestinationFile(fullength, expect)

# the header was added by moving the bytes under it to the end
# so now we reverse this process
# (this allows for decompression in-place ... not that we need to do this in the modern era with memory coming out of our ears)
restore_from_the_end = min(packedlength, HEAD_SIZE)
data = data[-restore_from_the_end:]+data[HEAD_SIZE:-restore_from_the_end]

src = SourceFile(data, shifter)


offset_modestore = MODESTORES[mode_store_choice]

for _ in xrange(unpacked):
	dest.send(src.peekm())

while not dest.done():
	x = 0
	while x!=5 and src.getbit()==0:
		x += 1
	base, read, mode = base_read_mode[x]
	print "basereadmode", base, read, mode

	length = base + src.getbits(read)
	offset = read_mode_store(src, offset_modestore, mode, "offset")
	unpacked = read_mode_store(src, MODESTORES[9], mode, "unpacked length")

	dest.copy(length, offset)

	for _ in xrange(unpacked):
		dest.send(src.peekm())

with open("answer.lbm", 'w') as f:
	dest.a.tofile(f)

#ilbmtoppm < answer.lbm | ppmtogif >answer.gif
