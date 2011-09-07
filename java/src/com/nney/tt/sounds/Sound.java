package com.nney.tt.sounds;

public class Sound {
	public final short[] data;
	private int freq;

	public Sound(short[] data, int freq) {
		this.freq = freq;
		assert data.length%2 == 0;
		this.data = data;
	}

	public static short[] upscaleUnsigned8(byte[] d) {
		short[] a = new short[d.length];
		for (int x=0; x<d.length; x++) {
			int v = d[x];
			v &= 255;
			v -= 128;
			v *= 250;
			a[x] = (short) v;
		}
		return a;
	}
	
	public static short[] upscaleMono(short[] d) {
		short[] a = new short[d.length*2];
		for (int x=0; x<d.length; x++) {
			short v = d[x];
			a[x*2] = v;
			a[x*2+1] = v;
		}
		return a;
	}

	public void freq(int f) {
		freq = f;
	}
	
	public int freq() {
		return freq;
	}
	
//	public void scale(float f) {
//		if (f==1) return;
//		for (int x=0; x<data.length; x++) {
//			data[x] = (short) (data[x]*f);
//		}
//	}
}
