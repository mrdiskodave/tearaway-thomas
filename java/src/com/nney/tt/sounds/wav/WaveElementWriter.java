package com.nney.tt.sounds.wav;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class WaveElementWriter {
	private DataOutputStream target;
	
	WaveElementWriter(OutputStream target) {
		this.target = new DataOutputStream(target);
	}
	
	void write32(String s) throws IOException {
		for (int x=0; x<4; x++) {
			target.writeByte(s.charAt(x));
		}
	}
	
	void write8(int x) throws IOException {
		target.writeByte(x);
	}

	void write16(int x) throws IOException {
		write8(x);
		target.writeByte(x>>8);
	}
	
	void write32(int x) throws IOException {
		write16(x);
		write16(x>>16);
	}

}
