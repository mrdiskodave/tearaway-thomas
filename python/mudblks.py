#!/usr/bin/python -3

import json


d = {}
b = 220
#z = [ 0,0,0,0,1,2,2,1,2,2,0,0,0,0,1,2,2,1,2,2,0,1,0,2,1,2,0,2 ]
#z = [ x-1 for x in z ]
#print repr(z)

z = [-1, -1, -1, -2, 0, 2, 1, 0, 1, 1,
 -1, -1, -1, -2, 0, 2, 1, 0, 1, 1,
  -2, 0, -1, 1, 0, 2, -2, 2]

for v in z:
	d.setdefault("slide:"+str(v), []).append(b)
	b += 1
	
print json.dumps(d, sort_keys=True, indent=4)

