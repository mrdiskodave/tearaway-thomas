#!/usr/bin/python -3

import json
import sys
import shelltools
import os
import re

s = """



	; WOOD MAPS
	dc.b	"w0.map",0	1 <SKIP>
	dc.b	"fast things first",0
	dc.b	35-20,15+35,1,11
	;	gems needed,time given,horizon,world*10+stage or00or01

	dc.b	"w9.map",0	2
	dc.b	"its like falling off a log",0
	dc.b	55-15,40+25,2,12

	dc.b	"w1.map",0	3
	dc.b	"number 3 - the larch",0
	dc.b	60-20,30+20,4,13

	dc.b	"w2.map",0	4 <SKIP>
	dc.b	"the worm that turned",0
	dc.b	70-25,40+20,1,14

	dc.b	"w3.map",0	6
	dc.b	"famous five",0
	dc.b	55-10,40+20,3,15

	dc.b	"w5.map",0	7
	dc.b	"rope and glory",0
	dc.b	70-20,60+5,7,16

	dc.b	"w6.map",0	8
	dc.b	"wood bee honey thief",0
	dc.b	85-25,75,6,17

	dc.b	"w7.map",0	9
	dc.b	"number 9 - the larch",0
	dc.b	60-5,45,3,18


*>
	; GHOST MAPS

	dc.b	"g0.map",0	21 <SKIP>
	dc.b	"tangled teleports",0
	dc.b	60-10,55+20,0,31

	dc.b	"g2.map",0	22
	dc.b	"haunted house",0
	dc.b	85-15,55+30,1,32

	dc.b	"g4.map",0	23
	dc.b	"the clock tower",0
	dc.b	70-10,40+20,2,33

	dc.b	"g5.map",0	24
	dc.b	"haunted hijinx",0
	dc.b	60-15,50+15,3,34

	dc.b	"g3.map",0	26
	dc.b	"ghosted then roasted",0
	dc.b	65-10,35+20,4,35

	dc.b	"g6.map",0	27 <SKIP>
	dc.b	"house 2",0
	dc.b	95-19,55+25,5,36

	dc.b	"g1.map",0	28 diagonal
	dc.b	"the ghost with the most",0
	dc.b	65-10,30+20,6,37

	dc.b	"g7.map",0	29
	dc.b	"the gallery",0
	dc.b	95-29,99,7,38

*>
	; ICE MAPS

	dc.b	"i3.map",0	31 BL to TL
	dc.b	"cool commotion",0
	dc.b	70-10,60,3,41

	dc.b	"i0.map",0	32 floors up in middle
	dc.b	"frozen frenzy",0
	dc.b	99-9,70+10,1,42

	dc.b	"i4.map",0	33
	dc.b	"polar panic",0
	dc.b	65-10,55+5,4,43

	dc.b	"i1.map",0	34 ice mountain <SKIP>
	dc.b	"ice is nice !not!",0
	dc.b	99-9,70+15,2,44

	dc.b	"i6.map",0	36
	dc.b	"wheel of fortune",0
	dc.b	45-5,40-15,7,45

	dc.b	"i7.map",0	37
	dc.b	"super slide",0
	dc.b	95-10,80+10,0,46

	dc.b	"i8.map",0	38
	dc.b	"the polar ponds",0
	dc.b	95-15,85+10,1,47

	dc.b	"i5.map",0	39 
	dc.b	"strange loop",0
	dc.b	99-19,99,6,48


"""


cycle = 0
levels = []
for l in s.split('\n'):
	l = re.sub(r"^\*.*", "", l)
	l = re.sub(r";.*", "", l)
	l = re.sub(r"\s+dc\.b\s+", "", l)
	l = l.strip()
	if l:
		if cycle==0:
			level = {}
			m = re.match(r'"(.*?)"', l)
			assert m
			level['map'] = m.group(1)
		if cycle==1:
			m = re.match(r'"(.*?)"', l)
			assert m
			level['title'] = m.group(1)
		if cycle==2:
			items = l.split(',')
			items = [ eval(x) for x in items ]
			level['gemsNeeded'] = items[0]
			level['timeGiven'] = items[1]
			level['horizon'] = items[2]
			levels.append(level)
		cycle += 1
		cycle %= 3

print json.dumps(levels, sort_keys=True, indent=4)







END_OF_FILE = """

*>
	; FUTURE MAPS

	dc.b	"f8.map",0	41 <SKIP>
	dc.b	"back to the future",0
	dc.b	33,80,6,51	.

	dc.b	"f9.map",0	42
	dc.b	"lift city",0
	dc.b	45,99,4,52

	dc.b	"f1.map",0	43
	dc.b	"pipe-nightmare",0
	dc.b	85-5,95,3,53

	dc.b	"f6.map",0	44
	dc.b	"teleport city",0
	dc.b	70,50,4,54	.

	dc.b	"f2.map",0	45 FRUIT
	dc.b	"fruit em up",0
	dc.b	0,20,7,00

	dc.b	"f7.map",0	46
	dc.b	"laser blazer",0
	dc.b	55,99,0,55	.

	dc.b	"f0.map",0	47
	dc.b	"i feel the need...",0
	dc.b	95,35,1,56

	dc.b	"f3.map",0	48
	dc.b	"the long hard shaft",0
	dc.b	45,70,5,57

	dc.b	"f5.map",0	49
	dc.b	"save the bast 'til last",0
	dc.b	95-25,99,2,58

	dc.b	"f4.map",0	50
	dc.b	"r u challenged?",0
	dc.b	0,60,3,05

skiptab	; skiponlevel,tolevel
	dc.b	1,6
	dc.b	4,9
	dc.b	13,18
	dc.b	21,27
	dc.b	27,29
	dc.b	34,38
	dc.b	41,43
	dc.b	-1,-1
	even
*>








	dc.b	"w8.map",0	5 FRUIT
	dc.b	"fruit em up",0
	dc.b	0,30,5,00

	dc.b	"g9.map",0	25 FRUIT
	dc.b	"fruit em up!",0
	dc.b	0,25,0,00

	dc.b	"i9.map",0	35 FRUIT
	dc.b	"fruit em up",0
	dc.b	0,25,5,00

*>
	; TOY MAPS

	dc.b	"t5.map",0	11
	dc.b	"the car ferry",0
	dc.b	30-5,55+20,0,21

	dc.b	"t1.map",0	12
	dc.b	"the choice is yours",0
	dc.b	75-15,75+20,0,22

	dc.b	"t2.map",0	13 <SKIP>
	dc.b	"this way up",0
	dc.b	70-15,55+15,0,23

	dc.b	"t10.map",0	14
	dc.b	"the big wheel",0
	dc.b	20-5,60,0,24

	dc.b	"t8.map",0	15 FRUIT
	dc.b	"fruit em up",0
	dc.b	0,30,0,00

	dc.b	"t4.map",0	16
	dc.b	"the crazy maze",0
	dc.b	40-5,70+20,0,25

	dc.b	"t7.map",0	17
	dc.b	"the choice is still yours",0
	dc.b	80-20,85+10,0,26

	dc.b	"t6.map",0	18
	dc.b	"up, up and (tear)away",0
	dc.b	70-5,65+10,0,27

	dc.b	"t3.map",0	19
	dc.b	"gems in high places",0
	dc.b	40-15,50+20,0,28

	dc.b	"t9.map",0	20
	dc.b	"r u challenged?",0
	dc.b	55,20,0,02













	dc.b	"w4.map",0	10
	dc.b	"r u challenged?",0
	dc.b	00,20,6,01

	dc.b	"g8.map",0	30
	dc.b	"r u challenged?",0
	dc.b	0,99,0,03

	dc.b	"i2.map",0	40 << falling challenge
	dc.b	"r u challenged?",0
	dc.b	0,30,2,04

"""
