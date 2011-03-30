import re

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

def load_defs(s):
	sprites = {}
	for line in s.split('\n'):
		line = line.strip()
		if line!='':
			m = re.match(r'"(.*)"\s*(\S+)?', line)
			if m:
				name, comment = m.group(1, 2)
				sprite = {}
				anims = sprite["anims"] = []
				sprites[name] = sprite
				if comment: sprite["comment"] = comment
			else:
				m = re.match(r'(\S*)\s*(\S+)?', line)
				if m:
					items, name = m.group(1, 2)
					items = re.split(r",", items)
					items = [ int(x) for x in items ]
					#print ">>>>>>>>>", repr(items)
					rate = items.pop(0)
					loop = items.pop()
					assert items
					if loop==-1:
						rpos = None
						if len(items)==1:
							assert rate==0	
						else:
							assert rate!=0
					else:
						rpos = len(items)+loop
						assert rate!=0
						#if rpos!=0: print "#MIDREPEAT!"
				anim = {}
				anims.append(anim)
				if name: anim['name'] = name
				if rate!=0: anim['rate'] = rate
				if rpos is not None: anim['repeatPos'] = rpos
				anim['frames'] = items
	return sprites
				
