package sandbox.lwjgl.demos.openal;

public class DataSrc {
	private byte[] b;

	public DataSrc(byte[] b) {
		this.b = b;
	}
	
	public int length() {
		return b.length;
	}
	
	public DataSrc(byte[] b, int p, int l) {
		this.b = extract(b, p, l);
	}

	private static byte[] extract(byte[] b, int p, int l) {
		assert p>=0;
		assert l>=0;
		assert p+l <= b.length;
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
	
	int ul(int p) {
		return (uw(p)<<16)+uw(p+2);
	}
	
	String g4cc(int p) {
		StringBuilder sb = new StringBuilder();
		for (int x=0; x<4; x++) sb.append((char)ub(p++));
		return sb.toString();
	}
	
	byte[] xx(int p, int l) {
		return extract(b, p, l);
	}
	
	DataSrc dsxx(int p, int l) {
		return new DataSrc(xx(p, l));
	}
	
}
