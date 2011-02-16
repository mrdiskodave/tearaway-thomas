import array
import struct
import sys

# blocks size in bytes
BLKSIZE = 2*16*4

# map size in blocks
MXS = 256
MYS = 128

woodRT = (
	( 40,24,29,53,83,84,64,85,88,89,69 ),
	( 20,4,9,33 ),
	( 60,44,49,73 ),
	( 304,305,324 ),
	( 370,371,350 ),
	( 276,296,278,298 ),
	( 277,297,279,299 ),
	( 332,334,336,338 ),
	( 333,335,337,339 ),
)

iceRT = (
	( 40,24,29,53,80,81,82,83,84,64,85,88,89,90,69,91,92 ),
	( 20,4,9,33 ),
	( 60,44,49,73 ),
)

ghostRT	= (
	( 104,124 ),
	( 107,127 ),
	( 85,86 ),
	( 145,146 ),
)


def apply_rt(map, rt):
	print "applying rt"
	c = 0
	import random
	for x in xrange(len(map)):
		for line in rt:
			if map[x] in line:
				map[x] = random.choice(line)
				c += 1
	print "{0}/{1} blocks changed".format(c, len(map))

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

def load_array_file(name):
	return array.array('B', load_file(name))

def get_word(data, idx):
	return data[idx]*256+data[idx+1]

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
			col = get_word(data, palbase+idx*2)
			if idx==0: col = 0
			if idx==7: col = 0xf0f
			r, g, b = col>>8&15, col>>4&15, col&15
			#r *= 16
			#g *= 16
			#b *= 16
			print "pal={0:04x} gives {1} {2} {3}".format(col, r, g, b)
			pa.append(( r, g, b ))
		pals.append(pa)
	#sys.exit(1)
	
	assert len(pals)==number_of_pals
	assert mapsegstart+number_of_blocks*BLKSIZE == mapsegend

	# just close around whatever we happen to need from the above
	def block_accessor(block_number):
		if block_number>=number_of_blocks: return None
		blkbase = mapsegstart+block_number*BLKSIZE
		pal = pals[block_pals[block_number]]
		br = blkbase
		lines = []
		for y in range(16):
			p2 = get_word(data, br)
			br += 2
			p1 = get_word(data, br)
			br += 2
			p0 = get_word(data, br)
			br += 2
			line = chunkify((p0,p1,p2), 16)
			line = [ pal[pix] for pix in line ]
			lines.append(line)
		return lines
	return block_accessor

def write_p6_header(f, w, h):
	f.write("P6\n")
	f.write("{0} {1}\n".format(w, h))
	f.write("15\n")

def write_p6_grid(f, lines):
	for line in lines:
		f.write(''.join([struct.pack('BBB', *pix) for pix in line ]))

def save_all_blocks(block_accessor):
	b = 0
	while 1:
		lines = block_accessor(b)
		if not lines: break;
		print "exporting block", b
		name = "b/blk"+str(b)+".ppm"
		with open(name, 'w') as f:
			write_p6_header(f, 16, 16)
			write_p6_grid(f, lines)
		b += 1

def get_map_from_level(level):
	# commision 64K of words
	map = array.array('H', [ 0 for _ in xrange(0x8000) ])
	# copy the compressed level in
	se = get_word(level, 0)
	print "length={0:04x}".format(se)
	assert se&1==0
	se >>= 1
	for x in xrange(se):
		map[x] = get_word(level, x*2)
	# fix it up
	se -= 1
	map[0] = map[se]
	# unpack it in situe
	# (it is also subject to DHp2 later)
	de = 0x8000
	while se!=0:
		se -= 1
		x = map[se]
		print "read={0:04x}".format(x)
		r = 1
		if x&0x8000:
			x ^= 0xffff
			se -= 1
			r = map[se]+1
		for _ in xrange(r):
			#print "src={0:08x} dest={1:08x} repeat={2:04x}/{3:04x} value={4:04x}".format(se, de, _, r, x)
			de -= 1
			map[de] = x
	assert de==0
	return map

level = load_array_file("tt_unpacked/w0.map")

def mapidx(x, y):
	return y*MXS+x

map = get_map_from_level(level)
apply_rt(map, woodRT)
print "Saving ..."
block_accessor = get_block_accessor("tt_unpacked/blkw")
mi = 0
with open("t.ppm", 'w') as f:
	write_p6_header(f, MXS*16, MYS*16)
	for ly in xrange(MYS):
		print ly, mi
		longlines = None
		for lx in xrange(MXS):
			b = map[mapidx(lx, ly)]
			mi += 1
			lines = block_accessor(b)
			if longlines:
				for line, longline in zip(lines, longlines):
					longline.extend(line)
			else:
				longlines = lines
		write_p6_grid(f, longlines)

#save_all_blocks(block_accessor)





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
