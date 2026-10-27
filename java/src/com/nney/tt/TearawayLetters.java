package com.nney.tt;

/**
 * The final challenge (Futureland's last stage): collect the letters of
 * TEARAWAY in order. From l_alien, letnum, lets_alive and fuzzydirs in s195.
 * 
 * Letters are numbered as in the original: 0 T, 1 E, 2 A, 3 R, 4 W, 5 Y. The
 * three A's are told apart by a "slot" (2, 4 or 6) set in the map.
 */
public final class TearawayLetters {
	public static final String NAMES = "tearwy";

	/** lets2get: which letter is wanted at each step. */
	private static final int[] ORDER = { 0, 1, 2, 3, 2, 4, 2, 5 };

	/** How many collected so far (letnum). */
	private int collected;

	/** lets_alive: the A's not yet collected, by slot (2, 4, 6). */
	private final boolean[] aAlive = { true, true, true, true, true, true, true, true };

	public int wanted() {
		return collected < ORDER.length ? ORDER[collected] : -1;
	}

	public boolean isWanted(int letter) {
		return wanted() == letter;
	}

	public void collect(int letter, int aSlot) {
		if (letter == 2) aAlive[aSlot] = false;
		collected++;
	}

	public boolean isComplete() {
		return collected >= ORDER.length;
	}

	/**
	 * fuzzydirs: for each advice screen (by its map block) the way to go for
	 * each step, then for the A's each one's priority (lower is nearer).
	 * 
	 * x, y, then directions for T E A R A W A Y (0 up, 1 right, 2 down, 3 left),
	 * then priorities for the A's in slots 2, 4 and 6.
	 */
	private static final int[][] HINTS = { //
			{ 76, 23, 1, 1, 1, 1, 0, 1, 1, 0, 3, 1, 2 }, //
			{ 15, 36, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, //
			{ 162, 37, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1 }, //
			{ 17, 57, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, //
			{ 74, 57, 3, 3, 3, 3, 0, 3, 1, 3, 3, 2, 1 }, //
			{ 165, 92, 2, 2, 3, 2, 3, 1, 3, 3, 1, 1, 1 }, //
			{ 57, 99, 3, 3, 3, 0, 0, 3, 0, 0, 1, 2, 3 }, //
			{ 90, 99, 3, 3, 2, 3, 3, 1, 3, 3, 1, 2, 3 }, //
			{ 38, 106, 3, 3, 2, 3, 3, 1, 3, 3, 1, 3, 2 } };

	/**
	 * Which way should the player go from the advice screen at this map block?
	 * 
	 * @return 0 up, 1 right, 2 down, 3 left, or -1 if this isn't one of the
	 *         screens the original knew about.
	 */
	public int hint(int blockX, int blockY) {
		for (int[] row : HINTS) {
			if (row[0] == blockX && row[1] == blockY) {
				int step = collected;
				if (step == 2 || step == 4 || step == 6) {
					// an A: point at the nearest one still there (scA)
					int best = 8;
					int bestSlot = 0;
					for (int slot = 2; slot <= 6; slot += 2) {
						int priority = row[10 + slot / 2 - 1];
						if (aAlive[slot] && priority < best) {
							best = priority;
							bestSlot = slot;
						}
					}
					step = bestSlot;
				}
				if (step >= ORDER.length) return -1;
				return row[2 + step];
			}
		}
		return -1;
	}
}
