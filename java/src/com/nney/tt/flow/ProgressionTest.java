package com.nney.tt.flow;

import junit.framework.TestCase;

public class ProgressionTest extends TestCase {
	/** Like the real game: 50 stages, the fifth of each world a bonus stage. */
	private static final Progression.StageInfo GAME = new Progression.StageInfo() {
		@Override
		public boolean isBonusStage(int level) {
			return level % 10 == 4;
		}

		@Override
		public int stageCount() {
			return 50;
		}
	};

	private static int next(int completed, boolean star, boolean[] secret) {
		return Progression.next(completed, star, secret, GAME);
	}

	public void testOneAfterAnother() {
		assertEquals(1, next(0, false, new boolean[] { false }));
		assertEquals(3, next(2, false, new boolean[] { false }));
	}

	public void testBonusStageSkippedWithoutTheSecret() {
		assertEquals(5, next(3, false, new boolean[] { false }));
	}

	public void testBonusStagePlayedWithTheSecretWhichIsUsedUp() {
		boolean[] secret = { true };
		assertEquals(4, next(3, false, secret));
		assertFalse(secret[0]);
	}

	public void testSecretKeptUntilABonusStageComesAlong() {
		boolean[] secret = { true };
		assertEquals(2, next(1, false, secret));
		assertTrue(secret[0]);
	}

	public void testStarSkips() {
		// skiptab in s195 counts from 1: 1->6, 4->9, 34->38
		assertEquals(5, next(0, true, new boolean[] { false }));
		assertEquals(8, next(3, true, new boolean[] { false }));
		assertEquals(37, next(33, true, new boolean[] { false }));
	}

	public void testStarOnAnOrdinaryStageDoesNothing() {
		assertEquals(2, next(1, true, new boolean[] { false }));
	}

	public void testAfterTheLastStage() {
		assertEquals(50, next(49, false, new boolean[] { false }));
		// a secret still unused at the very end makes no difference
		assertEquals(50, next(49, false, new boolean[] { true }));
	}
}
