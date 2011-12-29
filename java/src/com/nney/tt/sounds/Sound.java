package com.nney.tt.sounds;

public class Sound {
	public final short[] data;
	public final int freq;

	public Sound(short[] data, int freq) {
		this.freq = freq;
		assert data.length % 2 == 0;
		this.data = data;
	}

	// public void scale(float f) {
	// if (f==1) return;
	// for (int x=0; x<data.length; x++) {
	// data[x] = (short) (data[x]*f);
	// }
	// }
}
