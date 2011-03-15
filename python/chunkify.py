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

