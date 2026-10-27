import re
import os
import os.path

#
# look through the tmp_maps folder
# and the aliens.txt
# to see which aliens still need to implemented
#


reqw = {}
req = set()

#			"legacyData": "63000000000000000000000400000000000000000000"
def read_legacyData():
	dir = "tmp_maps"
	for name in os.listdir(dir):
		world = name[0]
		filename = os.path.join(dir, name)
		if os.path.isfile(filename):
			#print(filename)
			with open(filename) as file:
				for line in file:
					m = re.match(r'.*legacyData".*"(.*?)"', line)
					if m:
						data = m.group(1)
						type = int(data[:2], 16)
						reqw.setdefault(world, set()).add(type)
						req.add(type)

aliens = {}
			
#	dc.l	lift_alien,-just_draw_Vlift	0
def read_aliens():
	x = 0
	with open('aliens.txt') as file:
		for line in file:
			m = re.match(r'^.*dc\.l\s+(.*?),[-\s]*(\S+)\s+(\d+)', line)
			if m:
				alien, gfx, number = m.groups()
				number = int(number)
				print(alien, gfx, number, x)
				assert x==number
				x += 1
				aliens[number] = (alien, gfx)

def say(z):
	z = [ str(x) for x in sorted(z) ]
	return ','.join(z)+" "+str(len(z))

def summary():
	print(say(req))
	for k in reqw.keys():
		print(k)
		for z in reqw[k]:
			print("  ", z, repr(aliens[z]))

read_legacyData()
read_aliens()
summary()

