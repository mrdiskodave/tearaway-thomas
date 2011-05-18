package com.nney.tt.sprites;

import junit.framework.TestCase;

import com.nney.tt.gfx.SimpleImage;

public class LineInfoTest extends TestCase {
	public void testGenerator() throws Exception {
		// build an image with every possible line in it
		int bits = 3;
		SimpleImage si = SimpleImage.createEmpty(bits, 1 << bits);
		for (int y = 0; y < si.height(); y++) {
			for (int x = 0; x < si.width(); x++) {
				if ((y & (1 << x)) != 0) {
					si.put(x, y, 0xffffffff);
				}
			}
		}

		// generate some line info
		byte[] result = LineInfo.generate(si);

		// assert that it came out right
		assertEquals(16, result.length);
		assertPairEquals(result, 0, 0, 0);
		assertPairEquals(result, 1, 0, 1);
		assertPairEquals(result, 2, 1, 1);
		assertPairEquals(result, 3, 0, 2);
		assertPairEquals(result, 4, 2, 1);
		assertPairEquals(result, 5, 0, 3);
		assertPairEquals(result, 6, 1, 2);
		assertPairEquals(result, 7, 0, 3);
	}

	private void assertPairEquals(byte[] li, int i, int j, int k) {
		i *= 2;
		assertEquals(j, li[i]);
		assertEquals(k, li[i + 1]);
	}

	// TODO: unit test for collide()
}
