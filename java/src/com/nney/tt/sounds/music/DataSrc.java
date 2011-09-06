package com.nney.tt.sounds.music;

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
	
	int unsignedByte(int p) {
		return b[p]&0xff; 
	}
	
	int signedByte(int p) {
		return b[p];
	}
	
	int unsignedWord(int p) {
		return (unsignedByte(p)<<8)+unsignedByte(p+1);
	}
	
	int unsignedLong(int p) {
		return (unsignedWord(p)<<16)+unsignedWord(p+2);
	}
	
	String fourCharacterCode(int p) {
		StringBuilder sb = new StringBuilder();
		for (int x=0; x<4; x++) sb.append((char)unsignedByte(p++));
		return sb.toString();
	}
	
	byte[] rawData(int p, int l) {
		return extract(b, p, l);
	}
	
	DataSrc subDataSrc(int p, int l) {
		return new DataSrc(rawData(p, l));
	}
	
}
