package com.nney.tt.sounds;

public class SoundTools {
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
}
