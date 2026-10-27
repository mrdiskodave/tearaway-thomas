package com.nney.tt;

import junit.framework.TestCase;

public class TearawayLettersTest extends TestCase {
	private static final int T = 0, E = 1, A = 2, R = 3, W = 4, Y = 5;

	public void testSpellsTearawayInOrder() {
		TearawayLetters l = new TearawayLetters();
		int[] spelling = { T, E, A, R, A, W, A, Y };
		int[] aSlots = { 2, 4, 6 };
		int nextA = 0;
		for (int letter : spelling) {
			assertFalse(l.isComplete());
			assertTrue(l.isWanted(letter));
			assertFalse(l.isWanted((letter + 1) % 6));
			l.collect(letter, letter == A ? aSlots[nextA++] : 0);
		}
		assertTrue(l.isComplete());
		assertEquals(-1, l.wanted());
	}

	public void testHintsFromTheOriginalTable() {
		TearawayLetters l = new TearawayLetters();
		// screen at block (15,36): first the T is to the right, then the E left
		assertEquals(1, l.hint(15, 36));
		l.collect(T, 0);
		assertEquals(3, l.hint(15, 36));
		// not an advice screen
		assertEquals(-1, l.hint(1, 1));
	}

	public void testAHintGoesToTheNearestARemaining() {
		TearawayLetters l = new TearawayLetters();
		l.collect(T, 0);
		l.collect(E, 0);
		// screen (74,57): A priorities are 3, 2, 1 for slots 2, 4, 6 so slot 6
		// wins and its direction is column 2 + 6
		assertEquals(1, l.hint(74, 57));
		l.collect(A, 6);
		l.collect(R, 0);
		// slot 6 gone: slot 4 (priority 2), direction column 2 + 4
		assertEquals(0, l.hint(74, 57));
	}
}
