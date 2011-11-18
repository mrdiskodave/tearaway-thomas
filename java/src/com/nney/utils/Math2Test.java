package com.nney.utils;


import junit.framework.TestCase;

public class Math2Test extends TestCase {
	private static final int REPEAT = 1;

	public void test() throws Exception {
		assertEquals(Math2.findPowerOfTwo(16), 4);
	}

	public void testPercentPerformance() {
		StopWatch s = new StopWatch();
		int z = 0;
		for (int y = 0; y < REPEAT; y++) {
			for (int x = 0; x < Integer.MAX_VALUE; x++) {
				z += Math2.percent(x, 33);
			}
		}
		System.out.println("percent1:" + s.readMillisecondsFloat());
		System.out.println(z);
	}

	public void testPercent2Performance() {
		StopWatch s = new StopWatch();
		int z = 0;
		for (int y = 0; y < REPEAT; y++) {
			for (int x = 0; x < Integer.MAX_VALUE; x++) {
				z += Math2.percent2(x, 33);
			}
		}
		System.out.println("percent2:" + s.readMillisecondsFloat());
		System.out.println(z);
	}

}
