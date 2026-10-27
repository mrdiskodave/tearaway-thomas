import struct



def load_file(name):
	with open(name, 'rb') as f:
		return f.read()

def save_file(name, data):
	with open(name, 'wb') as f:
		f.write(data)


z = load_file("samples.bin")
for s in range(6):
	offset = struct.unpack_from('>L', z, s*4)[0];
	len = struct.unpack_from('>H', z,offset-2)[0]*2;
	data = z[offset:offset+len]
	name = "samp"+str(4+s)+".bin"
	print("saving", name)
	save_file(name, data)



