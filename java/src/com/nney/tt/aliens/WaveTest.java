package com.nney.tt.aliens;

import junit.framework.TestCase;

public class WaveTest extends TestCase {

	private String generate(int length, int max, int pause) {
		StringBuilder sb = new StringBuilder();
		for (int x = 0; x < length; x++) {
			if (x != 0) sb.append(',');
			sb.append(Wave.sawToothWaveWithPause(x, max, pause));
		}
		String actual = sb.toString();
		return actual;
	}

	public void test() throws Exception {
		assertEquals(">0,>1,<2,<1,>0,>1,<2,<1,>0,>1", generate(10, 2, 0));
		assertEquals("=0,=0,>0,>1,>2,>3,>4,=5,=5,<5,<4,<3,<2,<1,=0,=0,>0,>1,>2,>3", generate(20, 5, 2));
		assertEquals(">0,>1,<2,<1,>0", generate(5, 2, 0));
		assertEquals("=0,>0,>1,=2,<2,<1,=0,>0,>1,=2", generate(10, 2, 1));
	}
}
