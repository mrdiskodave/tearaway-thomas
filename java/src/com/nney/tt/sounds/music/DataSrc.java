package com.nney.tt.sounds.music;

public class DataSrc {
	public static class Broken extends RuntimeException {
		private static final long serialVersionUID = 1L;
		public Broken(String string) {
			super(string);
		}
	}
	
	private void check(int p, int l) {
		if (p<0 || l<0 || p+l>data.length) {
			throw new Broken("Illegal access - the file we are reading is corrupt?");
		}
	}
	
	private byte[] data;

	public DataSrc(byte[] b) {
		this.data = b;
	}
	
	public int length() {
		return data.length;
	}
	
	private static byte[] extract(byte[] b, int p, int l) {
		byte[] z = new byte[l];
		for (int x=0; x<l; x++) {
			z[x] = b[x+p];
		}
		return z;
	}
	
	public int unsignedByte(int p) {
		check(p, 1);
		return data[p]&0xff; 
	}
	
	public int signedByte(int p) {
		check(p, 1);
		return data[p];
	}
	
	public int unsignedWordBE(int p) {
		return (unsignedByte(p)<<8)+unsignedByte(p+1);
	}

	public int unsignedWordLE(int p) {
		return (unsignedByte(p+1)<<8)+unsignedByte(p);
	}

	public int unsignedLongBE(int p) {
		return (unsignedWordBE(p)<<16)+unsignedWordBE(p+2);
	}

	public int unsignedLongLE(int p) {
		return (unsignedWordLE(p+2)<<16)+unsignedWordLE(p);
	}

	public String fourCharacterCode(int p) {
		StringBuilder sb = new StringBuilder();
		for (int x=0; x<4; x++) sb.append((char)unsignedByte(p++));
		return sb.toString();
	}

	public byte[] rawData(int p, int l) {
		check(p, l);
		return extract(data, p, l);
	}

	public DataSrc subDataSrc(int p) {
		return subDataSrc(p, data.length-p);
	}

	public DataSrc subDataSrc(int p, int l) {
		return new DataSrc(rawData(p, l));
	}
}
