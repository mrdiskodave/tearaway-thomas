package com.nney.tt.mapper;

import junit.framework.TestCase;

public class StatusLinesTest extends TestCase {

	public void test() throws Exception {
		StatusLines f = new StatusLines(20);
		f.putLeft(0, "hello");
		f.putRight(0, "goodbye");
		f.putRight(1, "cheese");
		assertEquals("hello        goodbye", f.getLine(0));
		assertEquals("              cheese", f.getLine(1));
		assertNull(f.getLine(2));
	}
}
