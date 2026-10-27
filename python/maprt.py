#!/usr/bin/env python3

import json

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
	#print("applying rt")
	c = 0
	import random
	for x in range(len(map)):
		for line in rt:
			if map[x] in line:
				map[x] = random.choice(line)
				c += 1
	#print("{0}/{1} blocks changed".format(c, len(map)))

def validate_rt(name, mb, rt):
	for line in rt:
		for b in line:
			assert b<mb, str(b)


def print_rt(rt):
	print(json.dumps(rt, sort_keys=True, indent=4, separators=(', ', ': ')))	

if __name__ == "__main__":
	s = [ "wood", woodRT, "ice", iceRT, "ghost", ghostRT ]
	while s:
		name, rt = s[:2]
		s = s[2:]
		print()
		print('-' * 75)
		print(name)
		print_rt(rt)


