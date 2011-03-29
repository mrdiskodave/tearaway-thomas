import re

def load_file(name):
	with open(name, 'r') as f:
		return f.read()

s = load_file("gfx.s")
for line in s.split('\n'):
	line = line.strip()
	if line!='':
		m = re.match(r'"(.*)"\s*(\S+)?', line)
		if m:
			name, comment = m.group(1, 2)
			#print "HEADING", name, comment
			print
			if comment: print "#"+comment
			print "sprite:"+name
		else:
			m = re.match(r'(\S*)\s*(\S+)?', line)
			if m:
				items, comment = m.group(1, 2)
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
					if rpos!=0:
						print "#MIDREPEAT!"

				answer = []
				if comment: answer.append("name:"+comment)
				if rate!=0: answer.append("rate:"+str(rate))
				for x, f in enumerate(items):
					if x==rpos: answer.append("repeat")
					answer.append(str(f))
				print ",".join(answer)
				

