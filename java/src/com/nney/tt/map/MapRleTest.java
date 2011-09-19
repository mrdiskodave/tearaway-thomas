package com.nney.tt.map;

import java.util.Arrays;
import java.util.Random;

import junit.framework.TestCase;

public class MapRleTest extends TestCase {
	public void test() {
		for (int x = 200; x > 0; x--) {
			assertBlankRoundTripWorks(x);
		}
		assertBlankRoundTripWorks(0x8000);
		assertBlankRoundTripWorks(0x8001);
		assertBlankRoundTripWorks(0xffff);
		assertBlankRoundTripWorks(0x10000);
	}

	private void assertBlankRoundTripWorks(int x) {
		assertRoundTripWorks(new short[x]);
	}

	public void testKnown1() {
		short[] a = new short[10];
		assertEquals(2, BinaryMapRle.pack(a));
		assertEquals(9, a[0]);
		assertEquals(-1, a[1]);
	}

	public void testThatVariousRunsRoundTrip() {
		int size = 200;
		for (int start = 0; start < size; start++) {
			for (int end = start + 1; end < size; end++) {
				short[] a = new short[size];
				assertRoundTripWorks(a);
				Arrays.fill(a, start, end, (short) 7);
				assertRoundTripWorks(a);
			}
		}
	}

	public void testPseudorandomDataRoundTrips() {
		for (int size = 0; size < 1000; size++) {
			Random r = new Random(5);
			for (int t = 0; t < 30; t++) {
				short[] a = new short[size];
				for (int x = 0; x < size; x++) {
					a[x] = (short) r.nextInt(3);
				}
				assertRoundTripWorks(a);
			}
		}

	}

	private void assertRoundTripWorks(short[] given) {
		// System.out.println("---");
		// System.out.println(Arrays.toString(given));
		short[] working = Arrays.copyOf(given, given.length);
		int packedLength = BinaryMapRle.pack(working);
		// System.out.println(Arrays.toString(working));
		// System.out.println(packedLength);
		BinaryMapRle.unpack(working, packedLength);
		// System.out.println(Arrays.toString(working));

		assertArraysMatch(given, working);
	}

	private void assertArraysMatch(short[] given, short[] working) {
		assertEquals(given.length, working.length);
		for (int x = 0; x < given.length; x++) {
			assertEquals(given[x], working[x]);
		}
	}
}
