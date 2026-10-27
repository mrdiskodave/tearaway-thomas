
print("Calling glColor3ub:")
for x in range(32):
	shiftingIsWrong = x<<3
	scalingIsRight  = (255*x)//31
	print("for brightness {0:-2d}/31 don't pass 0x{1:02x}, do pass 0x{2:02x}.".format(x, shiftingIsWrong, scalingIsRight))

