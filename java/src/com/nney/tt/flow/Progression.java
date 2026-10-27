package com.nney.tt.flow;

import com.nney.tt.PersistedLevel;

/**
 * Which stage comes next. From the original's level advance code in s195
 * (complete_done, chkfruitem, check_star_skip and skiptab):
 * 
 * <ul>
 * <li>Collect the star on certain stages and you skip ahead.</li>
 * <li>Each world's bonus "fruit 'em up" stage is only played if you found the
 * secret on an earlier stage; otherwise it's skipped. Playing it uses the
 * secret up.</li>
 * </ul>
 */
final class Progression {
	private Progression() {
	}

	/** skiptab: {stage you collect the star on, stage you go to}, from 1. */
	private static final int[][] STAR_SKIPS = { { 1, 6 }, { 4, 9 }, { 13, 18 }, { 21, 27 }, { 27, 29 },
			{ 34, 38 }, { 41, 43 } };

	/** What the game needs to know about a stage. */
	interface StageInfo {
		boolean isBonusStage(int level);

		int stageCount();
	}

	static final StageInfo FROM_LEVEL_FILES = new StageInfo() {
		@Override
		public boolean isBonusStage(int level) {
			return "fruit".equals(new PersistedLevel(level, null).getLevelInfo().mode);
		}

		@Override
		public int stageCount() {
			return PersistedLevel.levelCount();
		}
	};

	/**
	 * @param completed
	 *            The stage just completed (from 0).
	 * @param gotStar
	 *            Did they collect the star on it?
	 * @param secret
	 *            Have they found a secret (and not used it yet)? Element 0 is
	 *            read and updated.
	 * @return The next stage (from 0), or {@link StageInfo#stageCount()} if
	 *         the game is complete.
	 */
	static int next(int completed, boolean gotStar, boolean[] secret, StageInfo stages) {
		int next = completed + 1;
		if (gotStar) {
			for (int[] skip : STAR_SKIPS) {
				if (skip[0] == completed + 1) next = skip[1] - 1;
			}
		}
		while (next < stages.stageCount() && stages.isBonusStage(next)) {
			if (secret[0]) {
				secret[0] = false;
				break;
			}
			next++;
		}
		return next;
	}
}
