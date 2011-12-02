package com.nney.tt.geom;

import junit.framework.TestCase;

public class BoxTest extends TestCase {
	public void test() throws Exception {
		Box small = new Box(3, 4, 6, 5);
		Box big = new Box(0, 0, 100, 100);

		// small inside big -- small is unchanged
		assertEquals(small.resideInside2(big), small);
		// big inside small - big is cropped down to be small
		assertEquals(big.resideInside2(small), small);
	}
}
