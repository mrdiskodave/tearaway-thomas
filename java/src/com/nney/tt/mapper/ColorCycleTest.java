package com.nney.tt.mapper;

import junit.framework.TestCase;

/**
 * The mapper's highlight: the cycle's value (0 up to 15 and back) is ORed into
 * every RGB nibble, so colours pulse brighter. Alpha is left alone.
 */
public class ColorCycleTest extends TestCase {
	public void testBrightens() throws Exception {
		ColorCycler cc = new ColorCycler();
		assertEquals("starts at 0: no change", 0x80000000, cc.process(0x80000000));
		cc.advance();
		cc.advance(); // (0.8 of a step per frame)
		assertEquals(0x80111111, cc.process(0x80000000));
		assertEquals("bits already set stay set", 0x80ff1155, cc.process(0x80ff0055));
	}

	public void testBrightest() throws Exception {
		ColorCycler cc = new ColorCycler();
		for (int i = 0; i < 19; i++) {
			cc.advance();
		}
		assertEquals(0x80ffffff, cc.process(0x80000000));
		for (int i = 0; i < 19; i++) {
			cc.advance();
		}
		assertEquals("and back down", 0x80000000, cc.process(0x80000000));
	}
}
