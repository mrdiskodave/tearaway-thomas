package com.nney.tt;

public class SimpleByteBuffer {
	private byte[] b = new byte[32];
	private int p = 0;

	public void rewind() {
		p = 0;
	}

	public byte get() {
		if (p >= b.length) return -1;
		return b[p++];
	}

	public void add(byte x) {
		if (p >= b.length) {
			b = moveInto(b.length * 2);
		}
		b[p++] = x;
	}

	private byte[] moveInto(int nl) {
		byte[] a = new byte[nl];
		System.arraycopy(b, 0, a, 0, p);
		return a;
	}

	public byte[] toByteArray() {
		return moveInto(p);
	}
}
