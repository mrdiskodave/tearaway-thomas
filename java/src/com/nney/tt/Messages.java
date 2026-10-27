package com.nney.tt;

public class Messages {
	private static final String PRESS_FIRE = "[p][c4]press jump";

	private static final String GOOD_LUCK = "[p][c5]good luck!" + PRESS_FIRE;

	private final static String LEVEL_TEXT = "[c1]level %s";

	private final static String CHAL_TEXT = LEVEL_TEXT + "[p][c5][k4]--challenge level--[k]";

	public static String levelStart(int level, String name, int gemsRequired, int gemsAvailable, int time) {
		return String.format(//
				LEVEL_TEXT + "[p][c5]<%s>" + //
						"[p][t2,3][hp30]" + //
						"[c0]gems required[e][c4]%d[e]" + //
						"[c0]gems on level[e][c4]%d[e]" + //
						"[c0]time[e][c4]%d[e]" + //
						GOOD_LUCK, //
				level, name, gemsRequired, gemsAvailable, time);
	}

	public static String raceChallenge(int level, int time) {
		return String.format(//
				CHAL_TEXT + //
						"[p][c]you have [c4]%s[c] seconds[n]" + //
						"to race to the finish" + //
						GOOD_LUCK, //
				level, time);
	}

	public static String levelComplete(int level, String name, int gemsCollected, int gemsRemaining, int timeLeft,
			boolean starSkip) {
		String t = String.format(//
				LEVEL_TEXT + "[p][c5]stage completed!" + //
						"[p][t2,3][hp30]" + //
						"[c0]gems collected[e][c4]%d[e]" + //
						"[c0]gems remaining[e][c4]%d[e]" + //
						"[c0]time left[e][c4]%d[e]", level, gemsCollected, gemsRemaining, timeLeft);

		if (gemsRemaining == 0 || starSkip) {
			t += "[p]";
		}
		if (gemsRemaining == 0) {
			t += "[c2][k5]perfect gem[n]collection![k][n]";
		}
		if (starSkip) {
			t += "[c2][k5]star skip[n]collected![k][n]";
		}

		t += PRESS_FIRE;

		return t;
	}

	public static String challengeComplete(int level, int timeLeft) {
		return String.format(//
				CHAL_TEXT + "[p][c5]challenge completed!" + //
						"[p][k][c]bonus [c2]10,000[c] awared!" + //
						PRESS_FIRE, //
				level, timeLeft);
	}

	/** The final challenge (chal_texts in s195). */
	public static String finalChallenge(int level) {
		return String.format(LEVEL_TEXT + "[p][c5][k4]--final challenge--[k]" + //
				"[p][c]collect the letters that[n]spell [c2]tearaway[c] (in order)" + //
				"[p][c]use screens to get advice!" + GOOD_LUCK, level);
	}

	/** ccomplete_text in s195. */
	public static String challengeCompleteExtraLife(int level, int secondsLeft) {
		return String.format(CHAL_TEXT + "[p][c5]challenge complete" + //
				"[p][c]with [c2]%d[c] seconds left.[n][c4]extra life awarded!" + //
				"[p][c2]well done!" + PRESS_FIRE, level, secondsLeft);
	}

	/** cfail_text in s195. */
	public static String challengeFailedNoExtraLife(int level) {
		return String.format(CHAL_TEXT + "[p][c1]challenge failed" + //
				"[p][c]out of time![n]sorry - no extra life!" + PRESS_FIRE, level);
	}

	public static String challengeFailed(int level) {
		return String.format(//
				CHAL_TEXT + "[p][c1]challenge failed!" + //
						"[p][k][c]no bonus awarded" + //
						PRESS_FIRE, //
				level);
	}

	public static String fruit(int levelNum, int timeGiven) {
		return String.format(//
				LEVEL_TEXT + "[p][c5][k4]--bonus stage--[k]" + //
						"[p][c]you have [c4]%s[c] seconds[n]" + //
						"to grab loadsa points!" + GOOD_LUCK, levelNum, timeGiven);
	}

	public static String fruitComplete(int levelNum) {
		return String.format(LEVEL_TEXT + "[p][c5][k4]--bonus stage--[k]" + //
				"[p][c]stage completed" + PRESS_FIRE, levelNum);
	}
}
