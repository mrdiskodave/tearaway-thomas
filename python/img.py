import array
import re

def write_p6_header(f, w, h, max):
	f.write("P6\n")
	f.write("{0} {1}\n".format(w, h))
	f.write("{0}\n".format(max))

class Img:
	BYTES_PER_PIXEL = 3

	@staticmethod
	def create(w, h):
		return Img._createNew(w, h, None)

	@staticmethod
	def createFromData(w, h, d):
		return Img._createNew(w, h, d)

	@staticmethod
	def _createNew(w, h, d):
		i = Img()
		i.base = 0
		i.stride = w*Img.BYTES_PER_PIXEL
		i.w = w
		i.h = h

		expect = w*h*Img.BYTES_PER_PIXEL
		if d is None:
			d = array.array('B', chr(0) * expect )

		i.d = d

		diff = expect-len(d)
		if diff!=0:
			if diff>0:
				msg = "File fell short by {0} byte(s)".format(diff)
			else:
				msg = "File has {0} extra byte(s) on the end".format(diff)
			assert False, msg
		return i

	@staticmethod
	def createFromP6(s):
		assert s[0] == 'P'
		assert s[1] == '6'
		s = s[2:]
		args = []
		while len(args)<3:
			m = re.match(r"(.*?)(#.*)?\n", s)
			assert m
			stuff = m.group(1)
			s = s[len(m.group()):]
			for x in stuff.split():
				args.append(int(x))

		width, height, max = args

		assert max==255
		return Img.createFromData(width, height, array.array('B', s))

	def clear(self, c):
		for y in xrange(self.h):
			for x in xrange(self.w):
				self.put(x, y, c)

	def isSubImage(self):
		return self.base!=0 or self.w*self.h*Img.BYTES_PER_PIXEL!=len(self.d)

	def _ca(self, x, y):
		assert 0<=x<self.w, "Can't address pixel {0},{1} in an image that measures {2},{3}".format(x, y, self.w, self.h)
		assert 0<=y<self.h, "Can't address pixel {0},{1} in an image that measures {2},{3}".format(x, y, self.w, self.h)
		return self.base+x*3+y*self.stride

	def view(self, x=0, y=0, w=None, h=None):
		if w is None: w = self.w - x
		if h is None: h = self.h - y
		assert x>=0
		assert y>=0
		assert w>=0
		assert h>=0
		assert x+w<=self.w
		assert y+h<=self.h
		i = Img()
		i.base = self._ca(x, y)
		i.stride = self.stride
		i.w = w
		i.h = h
		i.d = self.d
		return i

	def get(self, x, y):
		a = self._ca(x, y)
		return self.d[a], self.d[a+1], self.d[a+2]

	def put(self, x, y, c):
		#print "put {0},{1} with {2!r}".format(x, y, c)
		a = self._ca(x, y)
		self.d[a] = c[0]
		self.d[a+1] = c[1]
		self.d[a+2] = c[2]

	def overwrite(self, simg):
		assert simg
		w = min(self.w, simg.w)
		h = min(self.h, simg.h)
		w *= 3
		for y in xrange(h):
			srco = simg._ca(0, y)
			desto = self._ca(0, y)
			self.d[desto:desto+w] = simg.d[srco:srco+w]

	def findReplace(self, f, r):
		for y in xrange(self.h):
			for x in xrange(self.w):
				if self.get(x, y)==f:
					self.put(x, y, r)

	def map(self, f):
		for y in xrange(self.h):
			for x in xrange(self.w):
				c = self.get(x, y)
				self.put(x, y, f(c))

	def crop(self, c):
		left = 0
		while self.view(left, 0, w=1).test(c):
			left += 1

		top = 0
		while self.view(0, top, h=1).test(c):
			top += 1

		right = self.w-1
		while self.view(right, 0, w=1).test(c):
			right -= 1
		right += 1

		bottom = self.h-1
		while self.view(0, bottom, h=1).test(c):
			bottom -= 1
		bottom += 1

		width = right - left
		height = bottom - top
		answer = (left, top, width, height)
		return answer

	def test(self, c):
		for y in xrange(self.h):
			for x in xrange(self.w):
				a = self.get(x, y)
				#print "Got {0} from {1},{2}".format(a, x, y)
				if a!=c:
					return False
		return True

	def copy(self):
		i = Img.create(self.w, self.h)
		i.overwrite(self)
		return i

	def _unsub(self):
		if self.isSubImage():
			return self.copy()
		return self

	def saveP6(self, name):
		self = self._unsub()
		with open(name, 'w') as f:
			write_p6_header(f, self.w, self.h, 255)
			self.d.tofile(f)

	def saveRaw(self, f):
		self = self._unsub()
		self.d.tofile(f)

	def dump(self):
		for y in xrange(self.h):
			print [ self.get(x, y) for x in xrange(self.w) ]
