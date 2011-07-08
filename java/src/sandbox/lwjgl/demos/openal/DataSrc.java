package sandbox.lwjgl.demos.openal;

public class DataSrc {
	private byte[] b;

	public DataSrc(byte[] b, int p, int l) {
		this.b = extract(b, p, l);
	}

	private static byte[] extract(byte[] b, int p, int l) {
		byte[] z = new byte[l];
		for (int x=0; x<l; x++) {
			z[x] = b[x+p];
		}
		return z;
	}
	
	int ub(int p) {
		return b[p]&0xff; 
	}
	
	int sb(int p) {
		return b[p];
	}
	
	int uw(int p) {
		return (ub(p)<<8)+ub(p+1);
	}
	
	byte[] xx(int p, int l) {
		return extract(b, p, l);
	}
}
