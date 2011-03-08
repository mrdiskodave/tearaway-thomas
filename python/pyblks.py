import array
import struct
import sys
import shelltools
import img
import os
import re

# blocks size in bytes
BLKSIZE = 2*16*4

# map size in blocks
MXS = 256
MYS = 128

# palette size in colours
PALCOLS = 8
PALSIZE = PALCOLS*2

BLACK = (0,0,0)
WHITE = (0xff,0xff,0xff)
GREY  = (0x80,0x80,0x80)

CENTRE_MARKER = None
#CENTRE_MARKER = GREY

# the colour we'll use to mean "transparent"
# all Amiga colours are scaled up by 0x11 so 0x01 cannot happen
TRANS = ( 0xff, 0x01, 0xff )
TRANS2 = "/".join([ "{0:02x}".format(x) for x in TRANS ])    # i.e. "ff/01/ff"

NONE  = ( 0xff, 0x01, 0x01 )

NEWDATA = "newdata"

MAP_MAGIC = struct.unpack(">L", "PGBK")[0]

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

def validate_rt(name, mb, rt):
	for line in rt:
		for b in line:
			assert b<mb, str(b)

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

def load_array_file(name):
	return array.array('B', load_file(name))

def get_word(data, idx):
	return data[idx]*256+data[idx+1]

def raise_colour(c):
	r, g, b = c
	r *= 0x11
	g *= 0x11
	b *= 0x11
	return r, g, b

def get_a_palette(data, palbase):
	pa = []
	for idx in xrange(PALCOLS):
		col = get_word(data, palbase+idx*2)
		c = col>>8&15, col>>4&15, col&15
		c = raise_colour(c)
		print "pal={0:04x} gives {1:02x} {2:02x} {3:02x}".format(col, *c)
		pa.append(c)
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
	#print "planes:"+repr(p)
	answer = []
	for x in xrange(s):
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



def get_block_list(data, get_masks):

	magic, spals, blkpals, mapsegstart, mapsegend = struct.unpack('>LLLLL', data[:20])
	assert magic == MAP_MAGIC

	# skip the magic
	spals += 4
	blkpals += 4
	mapsegstart += 4
	mapsegend += 4

	number_of_blocks = mapsegstart-blkpals
	assert number_of_blocks%20==0

	block_pals = [ data[blkpals+x] for x in xrange(number_of_blocks) ] 

	if not get_masks:
		number_of_pals = (blkpals-spals)/PALSIZE
		pals = []
		for pal in xrange(number_of_pals):
			pa = get_a_palette(data, spals + pal*PALSIZE)
			pa[0] = ( 0x00, 0x00, 0x00 )
			pa[7] = TRANS
			pals.append(pa)
		assert len(pals)==number_of_pals

	assert mapsegstart+number_of_blocks*BLKSIZE == mapsegend

	answer = []
	for block_number in xrange(number_of_blocks):
		blkbase = mapsegstart+block_number*BLKSIZE
		br = blkbase
		i = img.Img.create(16, 16)

		if get_masks:
			i.clear(WHITE)
			GREY = (0xc0, 0xc0, 0xc0)
			for x in range(16):
				i.put(0, x, GREY)
				i.put(x, 0, GREY)
				i.put(15, x, GREY)
				i.put(x, 15, GREY)

			br += 2*16*3
		else:
			pal = pals[block_pals[block_number]]
		for y in xrange(16):
			if get_masks:
				p0 = get_word(data, br)
				br += 2
				line = chunkify([p0], 16)
				for x, pix in enumerate(line):
					if not pix:
						i.put(x, y, BLACK)
			else:
				p2 = get_word(data, br)
				br += 2
				p1 = get_word(data, br)
				br += 2
				p0 = get_word(data, br)
				br += 2
				line = chunkify((p0,p1,p2), 16)
				for x, pix in enumerate(line):
					i.put(x, y, pal[pix])
		answer.append(i)
	return answer

def change_suffix(s, ox, nx):
	ox = "."+ox
	nx = "."+nx
	sn, sx = os.path.splitext(s)
	assert sx == ox
	return sn + nx

assert change_suffix("hello.ppm", "ppm", "png")=="hello.png"

class Cascade:
	def __init__(self, f):
		self.f = f

	def getCurrentName(self):
		return self.f

	def assignNewName(self, n):
		os.remove(self.f)
		self.f = n

	def saveP6(self, i):
		i.saveP6(self.f)

	def toPNG(self):
		name = self.f
		newname = change_suffix(name, "ppm", "png")
		print "into", newname
		#f = "pnmtopng -force {0} >{1}"
		#f = "pnmtopng {0} >{1}"
		f = "pnmtopng -transparent =rgb:"+TRANS2+" {0} >{1}"
		shelltools.Cmd.shellf(f, name, newname).do().check()
		self.assignNewName(newname)

	def capture(self):
		a = load_file(self.f)
		os.remove(self.f)
		return a

def save_all_blocks(world, data):
	for mask in range(2):
		block_list = get_block_list(data, mask)
		rows = len(block_list)/20
		d = img.Img.create(20*16, rows*16)
		d.clear(NONE)
		for b, i in enumerate(block_list):
			x = b%20
			y = b/20
			x *= 16
			y *= 16
			d.view(x, y).overwrite(i)

		cas = Cascade(os.path.join(NEWDATA, "blocks", "{0}{1}.ppm".format(world, "m" if mask else "")))
		cas.saveP6(d)
		cas.toPNG()#map block

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
			print "src={0:08x} dest={1:08x} repeat={2:04x}/{3:04x} value={4:04x}".format(se, de, _, r, x)
			de -= 1
			map[de] = x
	assert de==0
	return map




def convert_map(block_data, name, rt):
	print "Converting", name
	block_list = get_block_list(block_data, False)

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

	def schem(l):
		#print repr(l)
		answer = []
		v = 0
		for t in l:
			if t:
				answer.append(v)
				v += 1
			else:
				answer.append(None)
		assert v==l.count(True), "{0} != {1}".format(v, l.count(True))
		return v, answer

	w, col = schem(col)
	h, row = schem(row)

	if rt:
		validate_rt(name, len(block_list), rt)
		apply_rt(map, rt)
	cas = Cascade(os.path.join(NEWDATA, "mapimg", name+".ppm"))
	with open(cas.getCurrentName(), 'w') as f:
		img.write_p6_header(f, w*16, h*16, 255)
		i = img.Img.create(w*16, 16)
		for mapy, scry in enumerate(row):
			if scry is not None:
				for mapx, scrx in enumerate(col):
					if scrx is not None:
						b = block_list[map[mapidx(mapx, mapy)]]
						i.view(16*scrx, 0).overwrite(b)
				i.saveRaw(f)
	cas.toPNG()#entire map

def convert_world(name, rt=None):
	data = load_array_file("odata/blk"+name)
	#save_all_blocks(name, data)

	for x in xrange(10):
		convert_map(data, name+str(x), rt)

def convert_worlds():
	convert_world("w", woodRT)
	convert_world("i", iceRT)
	convert_world("g", ghostRT)
	convert_world("t")
	convert_world("f")
	
# ---------------------------------------------------------------------------

class BookReader:
	def __init__(self, img, w=1, h=1, total_across=None):
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
	def lower_colour(c):
		r, g, b = c
		r >>= 4
		g >>= 4
		b >>= 4
		return r, g, b

	answer = img.Img.createFromP6(shelltools.Cmd.shellf("ilbmtoppm {0}", name).do(both=True).check().stdout)
	answer.map(lower_colour)
	answer.map(raise_colour)
	return answer
	
def convert_font():
	chars = "abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()'"
	i = load_ilbm("orig/gfx/other/bits/font.lbm")	
	i.findReplace((0x00,0x00,0x66), TRANS)
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

		cas = Cascade(os.path.join(NEWDATA, "font", "{0:03}.ppm".format(ord(c))))
		cas.saveP6(n.view(0, 0, w, None))
		cas.toPNG()#font character

def convert_tt():
	i = load_ilbm("orig/gfx/other/bits/tearaway.lbm")	
	i.findReplace((0x00,0x99,0xff),TRANS)
	r = BookReader(i, 32, 32, 8)
	for x in xrange(0, 64+8+3):
		b = r.start(x)
		print x, b
		n = img.Img.create(r.w, r.h)
		n.overwrite(i.view(*b))
		centre_and_save("0", "tt", x, n, -15, -29)
		#cas = Cascade(os.path.join(NEWDATA, "tearaway", "{0:03}.ppm".format(x)))
		#cas.saveP6(n)
		#cas.toPNG()#tearaway frame

def convert_bob(world, name):
	i = load_array_file("odata/"+world+name)

	#BOBaddx=0
	#BOBaddy=2
	#BOBsx=4
	#BOBsy=6
	#BOBpix15=8
	#BOBrastlen=10
	#BOBmaskadd=12
	#BOBdata=14

	MAGIC = struct.unpack(">L", name)[0]
	magic, framecount,  = struct.unpack(">LH", i[0:6])
	assert magic==MAGIC
	print framecount, "frame(s)"

	bobpal = get_a_palette(i, 6)

	offset = 6+PALSIZE


	for frame in xrange(framecount):
		addx, addy, sx, sy, pix15, rastlen, maskadd = struct.unpack(">hhHHHHH", i[offset:offset+14])
		offset += 14

		print "FRAME", frame

		#print addx, addy
		#print sx, sy
		#print pix15
		#print rastlen, maskadd
		#	-14 -37
		#	4 38
		#	6
		#	16 12

		assert sx%1==0
		unused = pix15-1
		assert unused>=0

		sprite = img.Img.create(sx*8-unused, sy)
		for y in xrange(sy):
			for x in xrange(sx/2):
				q = offset + x*2
				p2 = get_word(i, q)
				q += sx
				p1 = get_word(i, q)
				q += sx
				p0 = get_word(i, q)
				q += sx
				pm = get_word(i, q)

				line = chunkify((p0,p1,p2), 16)
				mask = chunkify((pm,), 16)
				for j in xrange(0, 16):
					if mask[j]:
						c = bobpal[line[j]]
					else:
						c = TRANS
					xd = x*16+j
					if xd<sprite.w:
						sprite.put(xd, y, c)
			offset += rastlen

		centre_and_save(world, name, frame, sprite, addx, addy)

def centre_and_save(world, name, frame, sprite, addx, addy):
	#
	# centre sprite on a canvas
	#
	# i thought about exporting the addx addy values just prepended to the PNG file
	# but then we're no longer using a standard format and it will limit our
	# options for editting this stuff later
	#

	CANVAS_SIZE = 161
	CANVAS_MIDDLE = CANVAS_SIZE//2

	canvas = img.Img.create(CANVAS_SIZE, CANVAS_SIZE)
	canvas.clear(TRANS)
	canvas.view(CANVAS_MIDDLE+addx, CANVAS_MIDDLE+addy).overwrite(sprite)
	# an assert fail on the above statement just means the canvas is too small and CANVAS_SIZE needs increasing

	#put a little dot in the middle so I can see we're hitting the right place
	if CENTRE_MARKER:
		canvas.put(CANVAS_MIDDLE, CANVAS_MIDDLE, CENTRE_MARKER)

	#framestr = "" if framecount==1 else "_{0}".format(frame);
	framestr = "_{0}".format(frame);
	cas = Cascade(os.path.join(NEWDATA, "bobs", "{0}{1}.ppm".format(world+name, framestr)))
	cas.saveP6(canvas)
	cas.toPNG()#bob frame

def convert_bobs():
	world = '0'
	s = load_file("ttgfx_defs.s")
	for line in s.split('\n'):
		m = re.match(r"([wigtf]).*_GFX", line)
		if m:
			world = m.group(1)
		m = re.match(r'.*"(....)"', line)
		if m:
			name = m.group(1)
			print world, name
			convert_bob(world, name)






convert_tt()
convert_bobs()	
#convert_font()
#convert_worlds()


