package com.nney.coroutines;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

public class CoroutineTest extends TestCase {
	public void testInterleaving() {
		final StringBuilder sb = new StringBuilder();

		Coroutine co = new Coroutine("interleave", c -> {
			for (int x = 0; x < 5; x++) {
				sb.append("x" + x);
				c.pause();
			}
		});

		int y = 0;
		do {
			sb.append("y" + y++);
		} while (co.step());

		assertEquals("y0x0y1x1y2x2y3x3y4x4y5", sb.toString());
		assertTrue(co.isFinished());
		assertFalse("stepping a finished coroutine is harmless", co.step());
	}

	public void testNothingRunsUntilFirstStep() {
		final boolean[] ran = new boolean[1];
		Coroutine co = new Coroutine("lazy", c -> ran[0] = true);
		assertFalse(ran[0]);
		assertFalse(co.step());
		assertTrue(ran[0]);
	}

	public void testSubclassStyle() {
		final List<Integer> got = new ArrayList<Integer>();
		Coroutine co = new Coroutine("subclass") {
			@Override
			protected void run() {
				for (int i = 0; i < 3; i++) {
					got.add(i);
					pause();
				}
			}
		};
		co.runToCompletion();
		assertEquals("[0, 1, 2]", got.toString());
	}

	public void testExceptionsReachTheCaller() {
		Coroutine co = new Coroutine("boom", c -> {
			c.pause();
			throw new IllegalArgumentException("kaboom");
		});
		assertTrue(co.step());
		try {
			co.step();
			fail();
		}
		catch (IllegalArgumentException ex) {
			assertEquals("kaboom", ex.getMessage());
		}
		assertTrue(co.isFinished());
	}

	public void testCloseRunsFinallyBlocks() {
		final StringBuilder sb = new StringBuilder();
		Coroutine co = new Coroutine("early", c -> {
			try {
				for (int x = 0;; x++) {
					sb.append("x" + x);
					c.pause();
				}
			}
			finally {
				sb.append("!");
			}
		});
		co.step();
		co.step();
		co.close();
		assertEquals("x0x1!", sb.toString());
		assertTrue(co.isFinished());
		co.close(); // twice is fine
	}

	public void testCloseBeforeStarting() {
		final boolean[] ran = new boolean[1];
		Coroutine co = new Coroutine("never", c -> ran[0] = true);
		co.close();
		assertFalse(co.step());
		assertFalse(ran[0]);
	}

	public void testStubbornBodyStillGetsClosed() {
		Coroutine co = new Coroutine("stubborn", c -> {
			for (int tries = 0; tries < 3; tries++) {
				try {
					c.pause();
				}
				catch (CoTerminated ex) {
					// bad manners, but we must still finish
				}
			}
		});
		co.step();
		co.close();
		assertTrue(co.isFinished());
	}

	public void testPauseFromOutsideIsAnError() {
		Coroutine co = new Coroutine("outside", c -> c.pause());
		co.step();
		try {
			co.pause();
			fail();
		}
		catch (IllegalStateException ex) {
			// expected
		}
		co.close();
	}

	public void testWaitUntil() {
		final int[] counter = new int[1];
		Coroutine co = new Coroutine("wait", c -> c.waitUntil(() -> counter[0] >= 3));
		int steps = 0;
		while (co.step()) {
			counter[0]++;
			steps++;
		}
		assertEquals(3, steps);
	}

	public void testManyCoroutinesAreCheap() {
		// would be 10,000 operating system threads with the old design
		List<Coroutine> all = new ArrayList<Coroutine>();
		final int[] total = new int[1];
		for (int i = 0; i < 10000; i++) {
			all.add(new Coroutine("many" + i, c -> {
				total[0]++;
				c.pause();
				total[0]++;
			}));
		}
		for (Coroutine c : all)
			c.step();
		for (Coroutine c : all)
			c.step();
		assertEquals(20000, total[0]);
	}
}
