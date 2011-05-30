package com.nney.tt.lwjgl;

import junit.framework.TestCase;

public class MultiCountingSetTest extends TestCase {
	public void test() throws Exception {
		MultiCountingSet<Integer, Integer> cs = new MultiCountingSet<Integer, Integer>();
		assertFalse(cs.contains(5));
		cs.add(5, 3);
		cs.add(5, 3);
		assertTrue(cs.contains(5));
		cs.remove(5, 3);
		assertFalse(cs.contains(5));
		
		cs.add(5, 3);
		cs.add(5, 4);
		assertTrue(cs.contains(5));
		cs.remove(5, 3);
		assertTrue(cs.contains(5));
		cs.remove(5, 3);
		assertTrue(cs.contains(5));
		cs.remove(5, 1);
		assertTrue(cs.contains(5));
		cs.remove(5, 4);
		assertFalse(cs.contains(5));
	}

}
