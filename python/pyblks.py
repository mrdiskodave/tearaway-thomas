import array
import struct
import sys

MAGIC = struct.unpack(">L", "PGBK")[0]

# http://en.wikipedia.org/wiki/Planar_(computer_graphics)
#
# p = bit plane values
# s = bit length of them
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
			
assert chunkify([1, 0, 7], 3)==[1, 1, 5]
assert chunkify([1, 0, 7], 4)==[0, 1, 1, 5]


if __name__ == "__main__":
	import sys

	def load_file(name):
		with open(name, 'r') as f:
			return f.read()

	def load_array_file(name):
		return array.array('B', load_file(name))

	def save_file(name, data):
		with open(name, 'w') as f:
			f.write(data)

	def getword(data, idx):
		return data[idx]*256+data[idx+1]

	data = load_array_file("tt_unpacked/blkw")
	data = array.array('B', data)
	magic, spals, blkpals, mapsegstart, mapsegend = struct.unpack('>LLLLL', data[:20])
	assert magic == MAGIC


	spals += 4
	blkpals += 4
	mapsegstart += 4
	mapsegend += 4

	number_of_blocks = mapsegstart-blkpals
	print "number_of_blocks", number_of_blocks
	print number_of_blocks

	block_pals = [ data[blkpals+x] for x in range(number_of_blocks) ] 

	number_of_pals = (blkpals-spals)/16
	print "number_of_pals", number_of_pals
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
		print pa
		pals.append(pa)
	
	assert len(pals)==number_of_pals
	assert mapsegstart+number_of_blocks*128 == mapsegend

	for b in range(number_of_blocks):
		answer = []
		answer.append("P3")
		answer.append("# block number "+str(b))
		answer.append("16 16")
		answer.append("255")
		blkbase = mapsegstart+b*128
		#for y in range(64):
		#	print hex(getword(data, blkbase+y*2))
		pal = pals[block_pals[b]]
		br = blkbase
		for y in range(16):
			p0 = getword(data, br)
			br += 2
			p1 = getword(data, br)
			br += 2
			p2 = getword(data, br)
			br += 2
			row = chunkify((p0,p1,p2), 16)
			row = [ pal[pix] for pix in row ]
			row = [ "{0:3} {1:3} {2:3}".format(pix[0], pix[1], pix[2]) for pix in row ]
			row = "   ".join(row)
			answer.append(row)
		answer.append("")
		answer.append("")
		answer = '\n'.join(answer)
		print "exporting block", b
		save_file("b/blk"+str(b)+".ppm", answer)



END = """

P3
# feep.ppm
4 4
15
0  0  0    0  0  0    0  0  0   15  0 15
0  0  0    0 15  7    0  0  0    0  0  0
0  0  0    0  0  0    0 15  7    0  0  0
15  0 15    0  0  0    0  0  0    0  0  0



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
