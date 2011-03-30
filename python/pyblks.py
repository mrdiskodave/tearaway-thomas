import json
import array
import struct
import sys
import shelltools
import os
import re

import img
import chunkify
import mapunpack
import maprt

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
CYAN  = (0x00,0xff,0xff)
YELLOW= (0xff,0xff,0x00)

CENTRE_MARKER = CYAN
#CENTRE_MARKER = None

# the colour we'll use to mean "transparent"
# all Amiga colours are scaled up by 0x11 so 0x01 cannot happen
TRANS = ( 0xff, 0x01, 0xff )
TRANS2 = "/".join([ "{0:02x}".format(x) for x in TRANS ])    # i.e. "ff/01/ff"

NONE  = ( 0xff, 0x01, 0x01 )

NEWDATA = "newdata"

MAP_MAGIC = struct.unpack(">L", "PGBK")[0]

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

def save_file(name, data):
	with open(name, 'w') as f:
		f.write(data)

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
				line = chunkify.chunkify([p0], 16)
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
				line = chunkify.chunkify((p0,p1,p2), 16)
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

	map = mapunpack.get_map_from_level(level)
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
		maprt.validate_rt(name, len(block_list), rt)
		maprt.apply_rt(map, rt)
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
	convert_world("w", maprt.woodRT)
	convert_world("i", maprt.iceRT)
	convert_world("g", maprt.ghostRT)
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

	def box(self, counter):
		x, y = self.start(counter)
		return x, y, self.w, self.h

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
	i = load_ilbm("orig/gfx/other/bits/font.lbm")	
	i.findReplace((0x00,0x00,0x66), TRANS)
	i.view(7*16, 2*11).fill(NONE)

	cas = Cascade(os.path.join(NEWDATA, "font", "font.ppm"))
	cas.saveP6(i.view(0, 0, None, 11*3))
	cas.toPNG()

def convert_topaz():
	src_data = load_array_file("orig/topaz.bin")
	pos = 0

	w = 16
	c = img.Img.create(8*w, 8*(128/w))
	r = BookReader(c, 8, 8)
	c.fill(TRANS)
	for idx in range(128):
		c1 = c.view(*r.box(idx))
		for y in range(8):
			data = src_data[pos]
			pos += 1
			for x in range(8):
				on = (data & (1<<(7-x)))!=0
				if on:
					c1.put(x, y, WHITE)

	cas = Cascade(os.path.join(NEWDATA, "font", "topaz.ppm"))
	cas.saveP6(c)
	cas.toPNG()
				

PLAYER_HANDLES = []
PLAYER_HANDLES.extend([ (0,0)  ] * 16) #walking
PLAYER_HANDLES.extend([ (0,1)  ] * 16) #jumping   e.g. draw the 32x32 one pixel lower (i.e. the handle is one pixel HIGHER in the 32x32)
PLAYER_HANDLES.extend([ (0,0)  ] *  6) #ladder use
PLAYER_HANDLES.extend([ (0,0), (-1, 0)  ] ) #standing
PLAYER_HANDLES.extend([ (0,0)  ] *  3) #head shaking
PLAYER_HANDLES.extend([ (0,0)  ] *  6) #flying
PLAYER_HANDLES.extend([ (0,0)  ] * 9) #monkeying
PLAYER_HANDLES.extend([ (-8,0) ] *  6) #shinning down the left of a rope
PLAYER_HANDLES.extend([ (4,0)  ] *  6) #shinning down the right of a rope
PLAYER_HANDLES.extend([
	(-6,0), # going round the rope
	(-4,0),
	(-1,0),
	(2,0),
	(3,0),
])

TT_FRAME_COUNT = 64+8+3
assert TT_FRAME_COUNT == len(PLAYER_HANDLES)

def convert_tt():
	bg = TRANS

	all_tt_frames = load_ilbm("orig/gfx/other/bits/tearaway.lbm")	
	all_tt_frames.findReplace((0x00,0x99,0xff),bg)
	r = BookReader(all_tt_frames, 32, 32, 8)
	exporter = Exporter("0tt")
	for x in xrange(TT_FRAME_COUNT):
		b = r.start(x)
		print x, b
		one_frame = img.Img.create(r.w, r.h)
		#for x in xrange(one_frame.w): print x, one_frame.get(x, 0)
		one_frame.overwrite(all_tt_frames.view(*b))
		c = one_frame.crop(bg)

		hx, hy = PLAYER_HANDLES[x]
		hx += c[0]
		hy += c[1]
		one_frame = one_frame.view(*c)
		
		#hx, hy = 0, 0
		exporter.save(one_frame, hx-15, hy-29)

		#cas = Cascade(os.path.join(NEWDATA, "tearaway", "{0:03}.ppm".format(x)))
		#cas.saveP6(n)
		#cas.toPNG()#tearaway frame
	exporter.done()

FRAMESKIP = {
	#"wbear": range(0,8),
	#"0tt": range(8, 16)+range(24,32)+[39]+range(46,49)+range(53, 57)+range(64,70),
	#"wabee": range(7,11),
	#"wbird": range(6,11),
	#"gfran": [0,1,2,3],
	#"ibear": range(15,
	}

print repr(FRAMESKIP)
#sys.exit(1)


def convert_bob(name):
	i = load_array_file("odata/"+name)
	exporter = Exporter(name)

	#BOBaddx=0
	#BOBaddy=2
	#BOBsx=4
	#BOBsy=6
	#BOBpix15=8
	#BOBrastlen=10
	#BOBmaskadd=12
	#BOBdata=14

	MAGIC = struct.unpack(">L", name[1:])[0]
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

				line = chunkify.chunkify((p0,p1,p2), 16)
				mask = chunkify.chunkify((pm,), 16)
				for j in xrange(0, 16):
					if mask[j]:
						c = bobpal[line[j]]
					else:
						c = TRANS
					xd = x*16+j
					if xd<sprite.w:
						sprite.put(xd, y, c)
			offset += rastlen

		exporter.save(sprite, addx, addy)
	exporter.done()

class Sprite:
	def __init__(self, i, addx, addy):
		self.i = i
		self.addx = addx
		self.addy = addy

	def centre_on_canvas(self):
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
		canvas.view(CANVAS_MIDDLE+self.addx, CANVAS_MIDDLE+self.addy).overwrite(self.i)
		# an assert fail on the above statement just means the canvas is too small and CANVAS_SIZE needs increasing

		#put a little dot in the middle so I can see we're hitting the right place
		if CENTRE_MARKER:
			canvas.put(CANVAS_MIDDLE, CANVAS_MIDDLE, CENTRE_MARKER)

		return canvas


NOT_MIRROR = 0
BEST_MIRROR = 100000

def is_mirror(a, b):
	w, h = a.i.w, a.i.h

	if w!=b.i.w: return NOT_MIRROR
	if h!=b.i.h: return NOT_MIRROR
	if a.addy!=b.addy: return NOT_MIRROR

	#print "Comparing pixels ..."
	score = 0
	
	for y in range(h):
		for x in range(w):
			ca = a.i.get(x, y) 
			cb = b.i.get(w-1-x, y)
			if ca==cb:
				score += 1
	#print "SCORE", score, "AREA", w*h
	fscore = (score*BEST_MIRROR )/(w*h)
	#print "ANSWER", fscore
	return fscore


MIRROR_ACTIONS = {
	# so the first question is
	# Stage1: Which one faces right?
	# Stage2: After which there maybe a addx disagreement that needs resolving!
	# Stage3: profit!
	
	'0tt_000+0tt_015': ('<',   0), # MIRROR score 100000
	'0tt_001+0tt_014': ('<',   0), # MIRROR score 100000
	'0tt_002+0tt_013': ('<',   0), # MIRROR score 100000
	'0tt_003+0tt_012': ('<',   0), # MIRROR score 100000
	'0tt_004+0tt_011': ('<',   0), # MIRROR score 100000
	'0tt_005+0tt_010': ('<',   0), # MIRROR score 100000
	'0tt_006+0tt_009': ('<',   0), # MIRROR score 100000
	'0tt_007+0tt_008': ('<',   0), # MIRROR score 100000
}

class Exporter:
	def __init__(self, name):
		self.name = name
		self.sprites = []
		self.ourFolder = os.path.join(NEWDATA, "bobs", name)
		shelltools.Cmd.shellf("mkdir -p {0}", self.ourFolder).do().check()

	def save(self, i, addx, addy):
		self.sprites.append(Sprite(i,addx,addy))

	@staticmethod
	def _framename(frame):
		return "{0:03}".format(frame);

#	def correct_mirrors(self):
#		killframe = set()
#		candidates = range(len(self.sprites))
#		while len(candidates)>=2:
#			first = candidates.pop(0)
#			best = NOT_MIRROR
#			choice = None
#			for other in candidates:
#				#print "Comparing frames {0} and {1}".format(self._framename(first), self._framename(other))
#				sfirst = self.sprites[first]
#				sother = self.sprites[other]
#				score = is_mirror(sfirst, sother)
#				if score>best:
#					#print "Scored improved"
#					best = score
#					choice = other
#					if score==BEST_MIRROR: break;
#			if best>=BEST_MIRROR*3/4:
#				af = -self.sprites[first].addx
#				ac = -self.sprites[choice].addx 
#				ac = self.sprites[choice].i.w-1-ac
#				assert af>=0
#				assert ac>=0
#				hd = ac-af
#
#
#				mdesc = self._framename(first, '-')+'+'+self._framename(choice, '-')
#
#
#				action, pixchange = MIRROR_ACTIONS.get(mdesc, ('?', hd))
#				if action=='?' and best==BEST_MIRROR:
#					action = '!'
#				print "\t'{0}': ('{1}', {2:3}), # MIRROR score {3:5}".format(mdesc, action, pixchange, best)
#				if action in ['<', '>']:
#					#print "remove the frame"
#					if action=='<':
#						yes = first
#						no  = choice
#					else:
#						yes = choice
#						no  = first
#					killframe.add(no)
#					
#				if action in ['<', '>', '!']:
#					#print "remove the candidate"
#					candidates.remove(choice)
#					pass
#
	def done(self):
		print "**** DONE!!!!!!!!!!!!!!!!!!"
		#self.correct_mirrors()
			
		defs = json.dumps(graphics_definitions[self.name], sort_keys=True, indent=4)
		save_file(os.path.join(self.ourFolder, "def.txt"), defs)
		for frame, sprite in enumerate(self.sprites):
			canvas = sprite.centre_on_canvas()

			cas = Cascade(os.path.join(self.ourFolder, self._framename(frame)+".ppm"))
			cas.saveP6(canvas)
			cas.toPNG()#bob frame

def convert_bobs():
	for name in graphics_definitions:
		if name!="0tt":
			convert_bob(name)


import gfxparse
graphics_definitions = gfxparse.load_defs(load_file("gfx.s"))

convert_tt()
#convert_bobs()	
#convert_font()
#convert_topaz()
#convert_worlds()

_END_ = """


PA_handles
	ds.w	16	0-15
	rept	16
	dc.b	0,1
	endr
	ds.w	26
	dc.b	-8,0	58 left rope
	dc.b	-8,0
	dc.b	-8,0
	dc.b	-8,0
	dc.b	-8,0
	dc.b	-8,0
	dc.b	4,0	64 right rope
	dc.b	4,0
	dc.b	4,0
	dc.b	4,0
	dc.b	4,0
	dc.b	4,0
	dc.b	-6,0	70
	dc.b	-4,0
	dc.b	-1,0
	dc.b	2,0
	dc.b	3,0

PA_runright	dc.b	105,00,01,02,03,04,05,06,07,-8
PA_runleft	dc.b	105,15,14,13,12,11,10,09,08,-8
PA_jumpright	dc.b	255,16,17,18,19,20,21,22,23,-8
PA_jumpleft	dc.b	255,24,25,26,27,28,29,30,31,-8
PA_stoodright	dc.b	0,38,-1
PA_stoodleft	dc.b	0,39,-1
PA_wobble	dc.b	128,40,41,42,41,-4
PA_climb	dc.b	128,32,33,34,35,36,37,36,35,34,33,-10
PA_flyright	dc.b	100,43,44,45,44,43,-1
PA_flyleft	dc.b	100,46,47,48,47,46,-1
PA_monkeyright	dc.b	80,49,50,51,52,-4
PA_monkeyleft	dc.b	80,56,55,54,53,-4
PA_monkeymid	dc.b	0,57,-1
PA_ropeleft	dc.b	128,58,59,60,61,62,63,-6
PA_roperight	dc.b	128,64,65,66,67,68,69,-6
PA_ropel2r	dc.b	200,70,71,72,73,74,64,-1
PA_roper2l	dc.b	200,74,73,72,71,70,58,-1

"""
