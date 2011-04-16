package com.nney.tt;

import junit.framework.TestCase;

public class MovementSlicerTest extends TestCase {
	public void test() throws Exception {
		assertTestsWorkInTheGivenDirection(1);
		assertTestsWorkInTheGivenDirection(-1);
	}

	private void assertTestsWorkInTheGivenDirection(int sign) {
		assertSmallTestWorks(sign);
		assertBigTestWorks(sign);
	}

	private void assertBigTestWorks(int sign) {
		MovementSlicer a = new MovementSlicer(sign*5);
		assertTrue(a.more());
		assertEquals(sign*2, a.next(2));
		assertTrue(a.more());
		assertEquals(sign*2, a.next(2));
		assertTrue(a.more());
		assertEquals(sign*1, a.next(2));
		assertDone(a);
	}

	private void assertSmallTestWorks(int sign) {
		MovementSlicer a = new MovementSlicer(sign*3);
		assertTrue(a.more());
		assertEquals(sign*1, a.next(1));
		assertTrue(a.more());
		assertEquals(sign*1, a.next(1));
		assertTrue(a.more());
		assertEquals(sign*1, a.next(1));
		assertDone(a);
	}

	private void assertDone(MovementSlicer a) {
		assertFalse(a.more());
		assertEquals(0, a.next(1));
		assertFalse(a.more());
	}

}
