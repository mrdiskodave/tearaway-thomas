package com.nney.tt.aliens;

import junit.framework.TestCase;

public class TestSawToothWave extends TestCase {
	private int sawToothWave(int pos, int size) {
		pos %= size * 2;
		if (pos >= size) {
			pos = size * 2 - pos;
		}
		return pos;
	}

	public void testname() throws Exception {
		int pos = 0;
		int size = 3;
		for (int x = 0; x < 20; x++) {
			System.out.println(sawToothWave(pos, size));
			pos++;
		}
	}
}
