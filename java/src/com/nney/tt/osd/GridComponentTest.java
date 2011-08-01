package com.nney.tt.osd;

import junit.framework.TestCase;

public class GridComponentTest extends TestCase {
	
	public void testEmpty() throws Exception {
		GridComponent g = new GridComponent(3, 7);
		assertEquals(0, g.width());
		assertEquals(0, g.height());
	}
	
	public void testJustify() {
		GridComponent g = new GridComponent(3, 3);
		g.setContent(1, 0, new SpacerComponent(40, 0));
		g.setContent(2, 0, new SpacerComponent(60, 0));
		g.setContent(0, 1, new SpacerComponent(0, 30));
		g.setContent(0, 2, new SpacerComponent(0, 80));
		assertEquals(100, g.width());
		assertEquals(110, g.height());

		// cell2,2:
		// x: 40 -- 100
		// y: 30 -- 110
		//
		// we're going to put w10,h20 into it
		MockComponent m = new MockComponent(10, 20);
		g.setContent(2, 2, m);

		// and drawing it at x1,y2
		// with different values for 'justify':

		g.draw(1, 2);
		assertEquals("41x32", m.drawnAt());
		g.setJustify(2, 2, Justify.SOUTHEAST);
		g.draw(1, 2);
		assertEquals("91x92", m.drawnAt());
		g.setJustify(2, 2, Justify.SOUTH);
		g.draw(1, 2);
		assertEquals("66x92", m.drawnAt());
		g.setJustify(2, 2, Justify.EAST);
		g.draw(1, 2);
		assertEquals("91x62", m.drawnAt());
	}

}
