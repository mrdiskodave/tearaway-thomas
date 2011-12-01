package com.nney.tt.map;

import java.util.Arrays;

import junit.framework.TestCase;

public class TextMapRleTest extends TestCase {
	public void assetResultMatchesAndRoundTripWorks(short[] input, String outpout) {
		assertEquals(outpout, TextMapRle.pack(input));

		short[] unpacked = new short[input.length];
		TextMapRle.unpack(unpacked, 0, input.length, outpout);
		assertTrue(Arrays.equals(unpacked, input));
	}

	public void test() throws Exception {
		// JUST worth it (3f,3f is a char longer)
		assetResultMatchesAndRoundTripWorks(new short[] { 63, 63 }, "2*3f");

		// a draw (2x1 is the same length)
		assetResultMatchesAndRoundTripWorks(new short[] { 1, 1 }, "1,1");

		// a general test
		assetResultMatchesAndRoundTripWorks(new short[] { 1, 1, 2, 1, 1, 1, 1, 1, 63 }, "1,1,2,5*1,3f");

		// a test of trailing zero stripping
		assetResultMatchesAndRoundTripWorks(new short[] { 0, 0, 1, 1, 2, 1, 1, 1, 1, 1, 63, 0 }, "0,0,1,1,2,5*1,3f");

		// tests of total zero stripping
		assetResultMatchesAndRoundTripWorks(new short[] { 0 }, "");
		assetResultMatchesAndRoundTripWorks(new short[] { 0, 0 }, "");
		assetResultMatchesAndRoundTripWorks(new short[] { 0, 0, 0 }, "");
	}
}
