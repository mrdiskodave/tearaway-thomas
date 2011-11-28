package com.nney.tt;

import java.util.Random;

import junit.framework.TestCase;

public class MovementSlicerTest extends TestCase {
	public void test() throws Exception {
		assertTestsWorkInTheGivenDirection(1);
		assertTestsWorkInTheGivenDirection(-1);
	}

	public void testMovement() throws Exception {
		Random r = new Random(1);
		for (int x = 0; x < 10000; x++) {
			int start = r.nextInt(200) - 100;
			int end = r.nextInt(200) - 100;
			assertMovementWorks(start, end);
		}
	}

	private void assertTestsWorkInTheGivenDirection(int sign) {
		assertSmallTestWorks(sign);
		assertBigTestWorks(sign);
	}

	private void assertBigTestWorks(int sign) {
		MovementSlicer a = new MovementSlicer(sign * 5);
		assertTrue(a.more());
		assertEquals(sign * 2, a.next(2));
		assertTrue(a.more());
		assertEquals(sign * 2, a.next(2));
		assertTrue(a.more());
		assertEquals(sign * 1, a.next(2));
		assertDone(a);
	}

	private void assertSmallTestWorks(int sign) {
		MovementSlicer a = new MovementSlicer(sign * 3);
		assertTrue(a.more());
		assertEquals(sign * 1, a.next(1));
		assertTrue(a.more());
		assertEquals(sign * 1, a.next(1));
		assertTrue(a.more());
		assertEquals(sign * 1, a.next(1));
		assertDone(a);
	}

	private void assertDone(MovementSlicer a) {
		assertFalse(a.more());
		assertEquals(0, a.next(1));
		assertFalse(a.more());
	}

	public void assertMovementWorks(int start, int end) {
		int diff = end - start;
		MovementSlicer ms = new MovementSlicer(diff);
		while (ms.more()) {
			start += ms.next(1);
		}
		assertEquals(start, end);
	}

}
