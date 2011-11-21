package com.nney.utils;


import junit.framework.TestCase;

public class Math2Test extends TestCase {
	private static final int REPEAT = 1;

	public void test() throws Exception {
		assertEquals(Math2.findPowerOfTwo(16), 4);
	}

	private void dontTestPercentPerformance() {
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

	private void dontTestPercent2Performance() {
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
	
	public void testBits() throws Exception {
		assertBits(0x55, "01010101");
		assertBits(0x33, "00110011");
		assertBits(0xaa, "10101010");
		assertBits(-1, "11111111111111111111111111111111");
		assertBits(0, "00000000000000000000000000000000");

	}

	private void assertBits(int value, String expectedBits) {
		int len = expectedBits.length();
		for (int bit=0; bit<len; bit++) {
			boolean actual = Math2.bitTest(value, bit);
			boolean expected = expectedBits.charAt(len-1-bit)=='1';
			assertEquals(expected, actual);
		}
	}

}
