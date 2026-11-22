package com.nney.utils;

import junit.framework.TestCase;

public class Math2Test extends TestCase {
	public void test() throws Exception {
		assertEquals(Math2.findPowerOfTwo(16), 4);
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
		for (int bit = 0; bit < len; bit++) {
			boolean actual = Math2.bitTest(value, bit);
			boolean expected = expectedBits.charAt(len - 1 - bit) == '1';
			assertEquals(expected, actual);
		}
	}

	public void testRounding() {
		assertEquals(0, Math2.roundUp(0, 10));
		assertEquals(10, Math2.roundUp(1, 10));
		assertEquals(10, Math2.roundUp(9, 10));
		assertEquals(10, Math2.roundUp(10, 10));
		assertEquals(20, Math2.roundUp(11, 10));

		assertEquals(0, Math2.roundDown(0, 10));
		assertEquals(0, Math2.roundDown(1, 10));
		assertEquals(0, Math2.roundDown(9, 10));
		assertEquals(10, Math2.roundDown(10, 10));
		assertEquals(10, Math2.roundDown(11, 10));
	}

}
