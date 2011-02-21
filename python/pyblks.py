import array
import struct
import sys
import shelltools
import img
import os

# blocks size in bytes
BLKSIZE = 2*16*4

# map size in blocks
MXS = 256
MYS = 128

TRANS = ( 0xff, 0x01, 0xff )

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
	#print "applying rt"
	c = 0
	import random
	for x in xrange(len(map)):
		for line in rt:
			if map[x] in line:
				map[x] = random.choice(line)
				c += 1
	#print "{0}/{1} blocks changed".format(c, len(map))

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

def load_array_file(name):
	return array.array('B', load_file(name))

def get_word(data, idx):
	return data[idx]*256+data[idx+1]

def get_a_palette(data, palbase):
	pa = []
	for idx in range(8):
		col = get_word(data, palbase+idx*2)
		r, g, b = col>>8&15, col>>4&15, col&15
		r *= 0x11
		g *= 0x11
		b *= 0x11
		#print "pal={0:04x} gives {1} {2} {3}".format(col, r, g, b)
		pa.append(( r, g, b ))
	return pa


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



def get_block_accessor(blk_filename):

	MAGIC = struct.unpack(">L", "PGBK")[0]

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
		pa = get_a_palette(data, spals + pal*16)
		pa[0] = ( 0x00, 0x00, 0x00 )
		pa[7] = TRANS
		pals.append(pa)
	
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

def write_p6_header(f, w, h, max):
	f.write("P6\n")
	f.write("{0} {1}\n".format(w, h))
	f.write("{0}\n".format(max))

def write_p6_grid(f, lines):
	for line in lines:
		f.write(''.join([struct.pack('BBB', *pix) for pix in line ]))

def post_process_ppm(name):
	assert name.endswith(".ppm")
	newname = name[:-3]+"png"
	print "into", newname
	shelltools.Cmd.shellf("pnmtopng {0} >{1}", name, newname).do().check()
	os.remove(name)

def save_all_blocks(world, block_accessor):
	b = 0
	while 1:
		lines = block_accessor(b)
		if not lines: break;
		name = "blocks/b{0}{1:x}.ppm".format(world, b)
		print "exporting", name
		with open(name, 'w') as f:
			write_p6_header(f, 16, 16, 255)
			write_p6_grid(f, lines)
		post_process_ppm(name)
		b += 1

def get_map_from_level(level):
	# commision 64K of words
	map = array.array('H', [ 0 for _ in xrange(0x8000) ])
	# copy the compressed level in
	se = get_word(level, 0)
	#print "length={0:04x}".format(se)
	assert se&1==0
	se >>= 1
	for x in xrange(se):
		map[x] = get_word(level, x*2)
	# fix it up
	se -= 1
	map[0] = map[se]
	# unpack it in situe
	# (it is also unpacked from DHp2 earlier)
	de = 0x8000
	while se!=0:
		# read a value pre-decrement
		se -= 1
		x = map[se]
		# what is it?
		if x&0x8000:
			# it is is a run
			# the data is the first value NOTed
			x ^= 0xffff
			# then there is another value which is a repeat count (in DBF form)
			se -= 1
			r = map[se]+1
		else:
			# it is just a single unpacked value
			r = 1
		for _ in xrange(r):
			#print "src={0:08x} dest={1:08x} repeat={2:04x}/{3:04x} value={4:04x}".format(se, de, _, r, x)
			de -= 1
			map[de] = x
	assert de==0
	return map




def convert_map(block_accessor, name, rt):
	print "Converting", name
	level = load_array_file("odata/"+name+".map")

	def mapidx(x, y):
		return y*MXS+x

	def is_full(map, x, y, dx, dy, r):
		for _ in xrange(r):
			if map[mapidx(x, y)]!=0: return True
			x += dx
			y += dy
		return False

	map = get_map_from_level(level)
	col = [ is_full(map, x, 0, 0, 1, MYS) for x in xrange(MXS) ]
	row = [ is_full(map, 0, y, 1, 0, MXS) for y in xrange(MYS) ]

	if rt: apply_rt(map, rt)
	fname = name+".ppm"
	with open(fname, 'w') as f:
		write_p6_header(f, col.count(True)*16, row.count(True)*16, 255)
		for ly in xrange(MYS):
			if row[ly]:
				longlines = None
				for lx in xrange(MXS):
					if col[lx]:
						lines = block_accessor(map[mapidx(lx, ly)])
						assert lines
						if longlines:
							for line, longline in zip(lines, longlines):
								longline.extend(line)
						else:
							longlines = lines
				write_p6_grid(f, longlines)
	post_process_ppm(fname)

def convert_world(name, rt=None):
	block_accessor = get_block_accessor("odata/blk"+name)
	save_all_blocks(name, block_accessor)
	for x in range(10):
		convert_map(block_accessor, name+str(x), woodRT)

def convert_worlds():
	convert_world("w", woodRT)
	convert_world("i", iceRT)
	convert_world("g", ghostRT)
	convert_world("t")
	convert_world("f")
	
# ---------------------------------------------------------------------------

class BookReader:
	def __init__(self, img, w, h, total_across=None):
		self.w = w
		self.h = h
		if total_across is None:
			total_across = img.w//w
		self.total_across = total_across

	def start(self, counter):
		y = counter / self.total_across
		x = counter % self.total_across
		x *= self.w
		y *= self.h
		return x, y

def load_ilbm(name):
	return img.Img.createFromP6(shelltools.Cmd.shellf("ilbmtoppm {0}", name).do(both=True).check().stdout)
	
def convert_font():
	chars = "abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()'"
	i = load_ilbm("orig/gfx/other/bits/font.lbm")	
	i.findReplace((0,0,96), TRANS)
	r = BookReader(i, 16, 11)
	for x, c in enumerate(chars):
		n = img.Img.create(r.w, r.h)
		n.overwrite(i.view(*r.start(x)))

		w = 16
		while True:
			assert w!=0
			sub = n.view(w-1, 0, 1, None)
			if not sub.test(TRANS): break
			w -= 1

		name = "font/"+str(ord(c))+".ppm"
		print "SAVE", name, c, w
		n.view(0, 0, w, None).saveP6(name)
		post_process_ppm(name)


def convert_tt():
	i = load_ilbm("orig/gfx/other/bits/tearaway.lbm")	
	i.findReplace((0,144,240),TRANS)
	r = BookReader(i, 32, 32, 8)
	for x in xrange(0, 64+8+3):
		b = r.start(x)
		print x, b
		n = img.Img.create(r.w, r.h)
		n.overwrite(i.view(*b))
		name = "tearaway/"+str(x)+".ppm"
		n.saveP6(name)
		post_process_ppm(name)

convert_worlds()
convert_font()
convert_tt()

# ---------------------------------------------------------------------------
# ( cd font && find . -name "*.ppm" -exec echo 'pnmtopng {} >{}.png' \; | sh )

