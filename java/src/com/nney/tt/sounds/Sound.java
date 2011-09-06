package com.nney.tt.sounds;

public class Sound {
	public final short[] data;

	public Sound(short[] data) {
		assert data.length%2 == 0;
		this.data = data;
	}

	public static Sound fromSam(byte[] d) {
		short[] a = new short[d.length*2];
		for (int x=0; x<d.length; x++) {
			// TODO: SCALE UP!!!! BUG 
			int v = d[x];
			v *= 256;
			a[x*2] = (short) v;
			a[x*2+1] = (short) v;
		}
		return new Sound(a);
	}
	
//	public void scale(float f) {
//		if (f==1) return;
//		for (int x=0; x<data.length; x++) {
//			data[x] = (short) (data[x]*f);
//		}
//	}
}
