import array

def get_word(data, idx):
	return data[idx]*256+data[idx+1]

def get_map_from_level(level):
	# commision 64K of words
	map = array.array('H', [ 0 for _ in range(0x8000) ])
	# copy the compressed level in
	se = get_word(level, 0)
	#print("length={0:04x}".format(se))
	assert se&1==0
	se >>= 1
	for x in range(se):
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
		for _ in range(r):
			#print("src={0:08x} dest={1:08x} repeat={2:04x}/{3:04x} value={4:04x}".format(se, de, _, r, x))
			de -= 1
			map[de] = x
	assert de==0
	return map

