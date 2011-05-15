package com.nney.tt.mapper;

import junit.framework.TestCase;

public class CycleTest extends TestCase {
	public void test1() throws Exception {
		Cycle c = new Cycle(1);
		assertEquals(0, c.next());
		assertEquals(1, c.next());
		assertEquals(0, c.next());
		assertEquals(1, c.next());
		assertEquals(0, c.next());
		assertEquals(1, c.next());
	}
	
	public void test3() throws Exception {
		Cycle c = new Cycle(3);
		assertEquals(0, c.next());
		assertEquals(1, c.next());
		assertEquals(2, c.next());
		assertEquals(3, c.next());
		assertEquals(2, c.next());
		assertEquals(1, c.next());
		assertEquals(0, c.next());
		assertEquals(1, c.next());
		assertEquals(2, c.next());
	}
	
	public void test3slow() throws Exception {
		Cycle c = new Cycle(3, 2, 1);
		assertEquals(0, c.next());
		assertEquals(0, c.next());
		assertEquals(1, c.next());
		assertEquals(1, c.next());
		assertEquals(2, c.next());
		assertEquals(2, c.next());
		assertEquals(3, c.next());
		assertEquals(3, c.next());
		assertEquals(2, c.next());
		assertEquals(2, c.next());
		assertEquals(1, c.next());
		assertEquals(1, c.next());
		assertEquals(0, c.next());
		assertEquals(0, c.next());
		assertEquals(1, c.next());
		assertEquals(1, c.next());
		assertEquals(2, c.next());
		assertEquals(2, c.next());
	}


}
