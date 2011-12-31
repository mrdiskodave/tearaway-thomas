package com.nney.tt.mapper;

import junit.framework.TestCase;

public class ScrollingWithMarginTest extends TestCase {
	public void test1() throws Exception {
		int margin = 64;
		int screen = 300;
		int canvas = 368;
		int spare = canvas - screen;

		ScrollingWithMargin swm = new ScrollingWithMargin(screen, canvas, margin);
		assertEquals(0, swm.scrollPosFromScreenPos(0));
		assertEquals(0, swm.scrollPosFromScreenPos(margin - 1));
		assertEquals(spare / 2, swm.scrollPosFromScreenPos(screen / 2));
		assertEquals(spare, swm.scrollPosFromScreenPos(screen - (margin - 1)));
		assertEquals(spare, swm.scrollPosFromScreenPos(screen - 1));
	}

	public void test2() throws Exception {
		// used to throw ArrayOutOfBounds ...
		new ScrollingWithMargin(300, 256, 64);
	}
}
