import struct

class MemPtr:
	def __init__(self, mem, shifter=128):
		self.mem = mem
		self.shiftreg = shifter
		self.pos = len(mem)

	def _peek(self, offset):
		return ord(self.mem[offset])

	def _peekm(self):
		self.pos -= 1
		answer = self._peek(self.pos)
		return answer

	def peekm(self):
		return self._peekm()

	def _getbit(self):
		#print "getbit", self.pos, hex(self.shiftreg)
		if self.shiftreg==128:
			#print "INIT"
			a = s = self._peekm()
			s &= 127
			s <<= 1
			s |= 1
			self.shiftreg = s
		else:
			#print "SHIFT"
			a = s = self.shiftreg
			s &= 127
			s <<= 1
			self.shiftreg = s
		a &= 128
		a >>= 7
		return a

	def getbit(self):
		a = self._getbit()
		print "BIT", a
		return a

	def getbits(self, count):
		answer = 0
		s = ''
		for _ in range(count):
			a = self._getbit()
			s = s + str(a)
			answer <<= 1
			answer |= a
		print "BITS", s, answer
		return answer

import array

class Result:
	
	def __init__(self, expect):
		print "Result!", expect
		self.a = array.array('B', chr(0)*expect)
		self.ptr = expect
		
	def isend(self, x):
		self.ptr -= 1
		self.a[self.ptr] = x
		
	def send(self, x):
		print "SENDING", hex(x)
		self.isend(x)

	def copy(self, length, offset):
		print "COPYING", length, offset
		for _ in xrange(length):
			self.isend(self.a[self.ptr+offset])

	def done(self):
		print "DONE?", self.ptr
		return self.ptr==0

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

def dump(m):
	s = ''
	for _ in xrange(80):
		s = str(m.getbit())+s
	print s


MODESTORE = (

	(
		( 0x00, 0x00, 0x00, 0x00 ),				#0	0
		( 0x01, 0x02, 0x02, 0x03 ),				#4	1
		( 0x03, 0x04, 0x06, 0x0d ),				#8	2
		( 0x0002, 0x0002, 0x0002, 0x0002 ),		#12	3
		( 0x0006, 0x000a, 0x000a, 0x0012 ),		#20	4
	),

	(
		( 0x04, 0x04, 0x04, 0x04 ),
		( 0x04, 0x04, 0x04, 0x04 ),
		( 0x05, 0x05, 0x05, 0x05 ),
		( 0x0020, 0x0020, 0x0020, 0x0020 ),
		( 0x0040, 0x0040, 0x0040, 0x0040 ),
	),

	(
		( 0x04, 0x05, 0x06, 0x06 ),
		( 0x05, 0x05, 0x05, 0x05 ),
		( 0x06, 0x06, 0x05, 0x05 ),
		( 0x0020, 0x0040, 0x0080, 0x0080 ),
		( 0x0060, 0x0080, 0x00c0, 0x00c0 ),
	),

	(
		( 0x04, 0x05, 0x06, 0x06 ),
		( 0x06, 0x06, 0x06, 0x06 ),
		( 0x07, 0x07, 0x07, 0x07 ),
		( 0x0020, 0x0040, 0x0080, 0x0080 ),
		( 0x00a0, 0x00c0, 0x0100, 0x0100 ),
	),

	(
		( 0x04, 0x05, 0x06, 0x07 ),
		( 0x06, 0x06, 0x07, 0x07 ),
		( 0x07, 0x08, 0x08, 0x08 ),
		( 0x0020, 0x0040, 0x0080, 0x0100 ),
		( 0x00a0, 0x00c0, 0x0180, 0x0200 ),
	),

	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x07, 0x08, 0x08 ),
		( 0x07, 0x08, 0x09, 0x09 ),
		( 0x0040, 0x0080, 0x0080, 0x0100 ),
		( 0x00c0, 0x0180, 0x0280, 0x0300 ),
	),

	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x08, 0x09 ),
		( 0x07, 0x09, 0x0a, 0x0a ),
		( 0x0040, 0x0080, 0x0080, 0x0100 ),
		( 0x00c0, 0x0280, 0x0280, 0x0500 ),
	),

	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x08, 0x09 ),
		( 0x07, 0x09, 0x0b, 0x0b ),
		( 0x0040, 0x0080, 0x0080, 0x0100 ),
		( 0x00c0, 0x0280, 0x0280, 0x0500 ),
	),

	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x09, 0x09 ),
		( 0x07, 0x0a, 0x0b, 0x0c ),
		( 0x0040, 0x0080, 0x0080, 0x0100 ),
		( 0x00c0, 0x0280, 0x0480, 0x0500 ),
	),

	(
		( 0x05, 0x06, 0x06, 0x07 ),
		( 0x06, 0x08, 0x09, 0x0a ),
		( 0x07, 0x0a, 0x0c, 0x0d ),
		( 0x0040, 0x0080, 0x0080, 0x0100 ),
		( 0x00c0, 0x0280, 0x0480, 0x0900 ),
	),

)

			#    0  1  2  3  4  5
LenBase		= ( 14, 6, 5, 4, 3, 2, )
LenRead		= (  8, 3, 0, 0, 0, 0, )
LenMode		= (  3, 3, 3, 2, 1, 0, )


MAGIC_SIZE = 4
HEAD_SIZE = 18

def read_mode_store(m, modestore, localmode):
	if m.getbit():
		return m.getbits(modestore[0][localmode])
	else:
		# MedLongMS
		if m.getbit():
			return m.getbits(modestore[1][localmode])+modestore[3][localmode]
		else:
		# LongMS
			return m.getbits(modestore[2][localmode])+modestore[4][localmode]

	###ReadModeStore
	###	moveq	#0,d1
	###	getbit
	###	bcc.s	MedLongMS
	###	move.b	0(a3,d6),d1
	###	getbits
	###	jmp	(a2)
	###
	###MedLongMS
	###	getbit
	###	bcc.s	LongMS
	###	move.b	4(a3,d6),d1
	###	getbits
	###	move.w	d6,d1
	###	add.w	d1,d1
	###	add.w	12(a3,d1.w),d0
	###	jmp	(a2)
	###LongMS
	###	move.b	8(a3,d6),d1
	###	getbits
	###	move.w	d6,d1
	###	add.w	d1,d1
	###	add.w	20(a3,d1.w),d0
	###	jmp	(a2)
	###	

data = load_file("bigTT.lbm")
assert data[:MAGIC_SIZE]=='DHp2'
fullength, packedlength, unpacked, packmode, shifter  = struct.unpack('>LLLBB', data[MAGIC_SIZE:HEAD_SIZE])
assert packedlength==len(data)
print "header", packmode, hex(shifter)

result = Result(fullength)

restore_from_the_end = min(packedlength, HEAD_SIZE)
print restore_from_the_end

print len(data)
data = data[-restore_from_the_end:]+data[HEAD_SIZE:-restore_from_the_end]
print len(data)

m = MemPtr(data, shifter)

for _ in xrange(unpacked):
	result.send(m.peekm())

# 01101001101000000011111111100000011000000011111111100000011000000011100110100000

modestore = MODESTORE[packmode]

while not result.done():
	v = 5
	while v!=0 and m.getbit()==0:
		v -= 1

	base = LenBase[v]
	read = LenRead[v]
	localmode = LenMode[v]

	print "basereadmode", base, read, localmode

	length = m.getbits(read)
	length += base

	offset = read_mode_store(m, modestore, localmode)
	unpacked = read_mode_store(m, modestore, localmode)

	result.copy(length, offset)
	for _ in xrange(unpacked):
		result.send(m.peekm())


with open("answer.lbm", 'w') as f:
	result.a.tofile(f)


orig = """

	opt	c-;,p+

getbit	MACRO
	; OUT	carry flag=next bit
	add.b   d7,d7
	bne.s   gbmore\@
	move.b  -(a0),d7
	addx.b  d7,d7
gbmore\@
	ENDM

getbits	MACRO
	moveq   #0,d0
	bra.s	gbnext\@
gbloop\@
	getbit
	addx.w  d0,d0
gbnext\@
	dbf     d1,gbloop\@
	ENDM


HeadSize=18
;d4=stop address
;d5=length
;d6=mode
;d7=BitShifter

;a0=source
;a1=dest
;a2=linkreg
;a3=MS ptr
;a4=unpackedMS
;a5=offsetMS
;a6=Variable Base

	lea	source(pc),a0
	bsr	UnpackFile
	rts
NotPacked
	rts

UnpackFile
	; IN	a0=file


	lea	VB(pc),a6

	lea	data-VB(a6),a4		=unpackedMS

	move.l	a0,d4
	move.l	a0,a1
	cmp.l	#"DHp2",(a1)+
	bne	NotPacked
	movem.l	(a1)+,d0/d1/d2
	move.b	(a1)+,d6
	move.b	(a1)+,d7
	; d0=FullLength
	; d1=PackLength
	; d2=Unpacked			# some will be left unpacked because we cannot keep on winning right to the top
	; d6=PackMode
	; d7=BitShifter

	ext.w	d6
	mulu	#MS_sizeof,d6
	lea	MS_sizeof(a4,d6.w),a5	=offsetMS

	moveq	#HeadSize,d6

	move.l	d1,d3
	sub.l	d6,d3
	cmp.l	d6,d3
	bls.s	SmallFile
	move.l	d6,d3
SmallFile

	lea	(a0,d3.w),a1
	lea	(a0,d1.w),a0

ReplaceHeader
	move.b	-(a0),-(a1)
	subq.w	#1,d3
	bne.s	ReplaceHeader

	lea	-HeadSize(a1,d1.w),a0
	lea	(a1,d0.w),a1
	bra.s	cu1
cu2	move.b	-(a0),-(a1)
cu1	subq.l	#1,d2
	bcc.s	cu2

LoopUnpack
	; get length
	moveq	#4,d2
LenType	getbit
	dbcs	d2,LenType

	add.w	d2,d2
	move.w	2+LenRead-VB(a6,d2.w),d1
	getbits
	add.w	2+LenBase-VB(a6,d2.w),d0
	move.w	2+LenMode-VB(a6,d2.w),d6
	move.w	d0,d5

	; d5 = length of pattern
	; d0 = 

	; copy pattern
	move.l	a5,a3
	lea	cont1(pc),a2
	jmp	(a6)
cont1	lea	1(a1,d0.w),a3
CopyPat	move.b	-(a3),-(a1)
	dbf	d5,CopyPat

	; copy unpacked data
	move.l	a4,a3
	lea	NextUPD(pc),a2
	jmp	(a6)

CopyUPD	move.b	-(a0),-(a1)
NextUPD	dbf	d0,CopyUPD

	cmp.l	a0,d4
	bne	LoopUnpack
	rts
data	incbin	"unpack.data"

LenBase
	dc.w	14-1
	dc.w	06-1
	dc.w	05-1
	dc.w	04-1
	dc.w	03-1
	dc.w	02-1
LenRead
	dc.w	8
	dc.w	3
	dc.w	0
	dc.w	0
	dc.w	0
	dc.w	0
LenMode
	dc.w	3
	dc.w	3
	dc.w	3
	dc.w	2
	dc.w	1
	dc.w	0
VB


ReadModeStore
	moveq	#0,d1
	getbit
	bcc.s	MedLongMS
	move.b	0(a3,d6),d1
	getbits
	jmp	(a2)

MedLongMS
	getbit
	bcc.s	LongMS
	move.b	4(a3,d6),d1
	getbits
	move.w	d6,d1
	add.w	d1,d1
	add.w	12(a3,d1.w),d0
	jmp	(a2)
LongMS
	move.b	8(a3,d6),d1
	getbits
	move.w	d6,d1
	add.w	d1,d1
	add.w	20(a3,d1.w),d0
	jmp	(a2)


MSbits=0
MSwidths=12
MS_sizeof=28


source
	incbin	genam.DHp2
	ds.b	1024*24
result
	incbin	C:genam
end

	end

>>> ''.join([ hex(ord(c))[2:] for c in "DHp2" ])
'44487032'
>>> 0x44487032
1145598002
>>>



"""

