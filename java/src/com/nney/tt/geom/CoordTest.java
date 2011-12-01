package com.nney.tt.geom;

import junit.framework.TestCase;

public class CoordTest extends TestCase {

	public void test() throws Exception {
		assertEquals(new Coord(0, 1), new Coord(1, 17).div2(16));

		assertEquals(new Coord(0, -1), new Coord(-1, -17).div2(16));

		assertEquals(new Coord(-1, -2), new Coord(-1, -17).asr2(4));

	}
}
