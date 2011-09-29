package com.nney.tt.aliens;

import junit.framework.TestCase;

public class TestSawToothWave extends TestCase {
	
	public static int sawToothWave(int x, int max, int pause) {
		int cycleLength = 2*(max + pause);
		x %= cycleLength;
		if (x<pause) {
			return 0;
		}
		x-=pause;
		if (x<max) {
			return x;
		}
		x-=max;
		if (x<=pause) {
			return max;
		}
		x-=pause;
		return max-x;
	}

	private String generate(int length, int max, int pause) {
		StringBuffer sb = new StringBuffer(); 
		for (int x = 0; x < length; x++) {
			if (x!=0) sb.append(',');
			sb.append(sawToothWave(x, max, pause));
		}
		String actual = sb.toString();
		System.out.println(actual);
		return actual;
	}

	public void test() throws Exception {
		assertEquals("0,0,0,1,2,3,4,5,5,5,4,3,2,1,0,0,0,1,2,3", generate(20, 5, 2));
		assertEquals("0,1,2,1,0", generate(5, 2, 0));
		assertEquals("0,1,2,1,0,1,2,1,0,1", generate(10, 2, 0));
		assertEquals("0,0,1,2,2,1,0,0,1,2", generate(10, 2, 1));
	}

}
