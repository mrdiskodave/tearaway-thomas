import array
import struct
import sys


def get_block_accessor(blk_filename):

	MAGIC = struct.unpack(">L", "PGBK")[0]

	# http://en.wikipedia.org/wiki/Planar_(computer_graphics)
	#
	# p = the bit-plane values
	# s = the number of bits in use in each value
	# returns = values read across the planes (i.e. the chunky values)
	# * values come out in plane MSB to LSB order
	# * p[0] produces the new chunky MSB
	# * p[s-1] produces the new chunky LSB
	def chunkify(p, s):
		answer = []
		for x in range(s):
			ba = 0
			for c in p:
				bitpos = s-x-1
				ba <<= 1
				ba |= (c & (1<<bitpos)) >> bitpos
			answer.append(ba)
		return answer

	# see that bitwise gets flipped around to become bytewise:
	assert chunkify([0b001,
                     0b000,
                     0b111], 3)==[0b001,
                                  0b001,
                                  0b101]
	assert chunkify([0b0001,
	                 0b0000,
					 0b0111], 4)==[0b000,
					               0b001,
					               0b001,
                                   0b101]

	def load_file(name):
		with open(name, 'r') as f:
			return f.read()

	def load_array_file(name):
		return array.array('B', load_file(name))

	def getword(data, idx):
		return data[idx]*256+data[idx+1]


	data = load_array_file(blk_filename)
	data = array.array('B', data)
	magic, spals, blkpals, mapsegstart, mapsegend = struct.unpack('>LLLLL', data[:20])
	assert magic == MAGIC

	spals += 4
	blkpals += 4
	mapsegstart += 4
	mapsegend += 4

	number_of_blocks = mapsegstart-blkpals

	block_pals = [ data[blkpals+x] for x in range(number_of_blocks) ] 

	number_of_pals = (blkpals-spals)/16
	pals = []
	for pal in range(number_of_pals):
		palbase = spals + pal*16
		pa = []
		for idx in range(8):
			col = getword(data, palbase+idx*2)
			r, g, b = col>>8&15, col>>4&15, col&15
			r *= 16
			g *= 16
			b *= 16
			pa.append(( r, g, b ))
		pals.append(pa)
	
	assert len(pals)==number_of_pals
	assert mapsegstart+number_of_blocks*128 == mapsegend

	# just close around whatever we happen to need from the above
	def answer(block_number):
		if block_number>=number_of_blocks: return None
		blkbase = mapsegstart+block_number*128
		pal = pals[block_pals[block_number]]
		br = blkbase
		lines = []
		for y in range(16):
			p0 = getword(data, br)
			br += 2
			p1 = getword(data, br)
			br += 2
			p2 = getword(data, br)
			br += 2
			line = chunkify((p0,p1,p2), 16)
			line = [ pal[pix] for pix in line ]
			lines.append(line)
		return lines
	return answer

def write_p6_header(f, w, h):
	f.write("P6\n")
	f.write("{0} {1}\n".format(w, h))
	f.write("255\n")

def write_p6_grid(f, lines):
	for line in lines:
		f.write(''.join([struct.pack('BBB', *pix) for pix in line ]))


ba = get_block_accessor("tt_unpacked/blkw")
b = 0
while 1:
	lines = ba(b)
	if not lines: break;
	print "exporting block", b
	name = "b/blk"+str(b)+".ppm"
	with open(name, 'w') as f:
		write_p6_header(f, 16, 16)
		write_p6_grid(f, lines)
	b += 1





END = """

P3
# feep.ppm
4 4
15
0  0  0    0  0  0    0  0  0   15  0 15
0  0  0    0 15  7    0  0  0    0  0  0
0  0  0    0  0  0    0 15  7    0  0  0
15  0 15    0  0  0    0  0  0    0  0  0

-               line = [ "{0:3} {1:3} {2:3}".format(pix[0], pix[1], pix[2]) for pix in line ]
-               line = "  ".join(line)
-               answer.append(line)
^^^ that is how you format into a P3
just that we are doing P6 now as its >4 times smaller


	move.l  AKblocks,a0^M
	cmp.l   #"PGBK",(a0)+^M
	bne ERnoPGBK^M
	^M
	movem.l (a0),a1/a2/a3/a4^M
	add.l   a0,a1^M
	add.l   a0,a2^M
	add.l   a0,a3^M
	add.l   a0,a4^M
	addq.l  #2,a1^M
	move.l  a1,spals^M
	subq.l  #2,a1^M
	move.l  a2,blkpals^M
	move.l  a3,MapSegBase^M
	move.l  a4,MapSegEnd^M
	^M
	move.l  a3,d0^M
	sub.l   a2,d0^M
	move.w  d0,blk_cnt^M

when done do

find . -name '*.ppm' -printf 'pnmtopng <%p >%p.png\n' | sh
rename -v 's/ppm.png/png/' *
rm *.ppm

"""
