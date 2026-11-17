package com.nney.tt.osd;

import junit.framework.TestCase;

public class ResizableGridTest extends TestCase {
	public void test() throws Exception {
		ResizableGrid<String> rg = new ResizableGrid<>(2, 2);
		assertEquals("null,null|null,null", rg.dump());
		rg.set(0, 0, "a");
		rg.set(1, 0, "b");
		rg.set(0, 1, "c");
		rg.set(1, 1, "d");
		assertEquals("a,b|c,d", rg.dump());
		rg.setSize(2, 3);
		assertEquals("a,b|c,d|null,null", rg.dump());
		rg.setSize(3, 3);
		rg.set(1, 2, "foo");
		assertEquals("a,b,null|c,d,null|null,foo,null", rg.dump());
		rg.setSize(1, 1);
		assertEquals("a", rg.dump());
		rg.setSize(0, 0);
		assertEquals("", rg.dump());
	}
}
