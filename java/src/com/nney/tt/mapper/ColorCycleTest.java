package com.nney.tt.mapper;

import junit.framework.TestCase;

public class ColorCycleTest extends TestCase {
	public void test() throws Exception {
		ColorCycle cc = new ColorCycle();
		assertEquals(0x80ff0000, cc.process(0x80ff0055));
		cc.advance();
		assertEquals(0x80ff0011, cc.process(0x80ff0055));
	}
}
