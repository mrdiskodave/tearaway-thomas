package com.nney.tt;

import junit.framework.TestCase;

public class LatchTest extends TestCase {
	public void test() throws Exception {
		Latch l = new Latch();
		assertTrue(l.can(0));
		assertFalse(l.can(1));
		
		assertTrue(l.can(5));
		assertFalse(l.can(5));
		assertFalse(l.can(5));
		assertFalse(l.can(5));
		assertFalse(l.can(6));
		assertFalse(l.can(6));
		assertFalse(l.can(7));
		assertFalse(l.can(8));
		assertFalse(l.can(9));
		assertTrue(l.can(11));
		
		
		
	}
}
