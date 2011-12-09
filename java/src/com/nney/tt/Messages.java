package com.nney.tt;

public class Messages {
	private final static String LEVEL_TEXT = "[c1]level %s";

	private final static String CHAL_TEXT = LEVEL_TEXT + "[p][c5][k4]--challenge level--[k]";

	public static String levelStart(int level, String name, int gemsRequired, int gemsAvailable, int time) {
		return String.format(//
				LEVEL_TEXT + "[p][c5]<%s>" + //
						"[p][t2,3][hp30]" + //
						"[c0]gems required[e][c4]%d[e]" + //
						"[c0]gems on level[e][c4]%d[e]" + //
						"[c0]time[e][c4]%d[e]" + //
						"[p][c5]good luck![p][c4]press jump", //
				level, name, gemsRequired, gemsAvailable, time);
	}

	public static String raceChallenge(int level, int time) {
		return String.format(//
				CHAL_TEXT + //
						"[p][c]you have [c4]%s[c] seconds[n]" + //
						"to race to the finish" + //
						"[p][c5]good luck![p][c4]press jump", //
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

		t += "[p][c4]press jump";

		return t;
	}

	public static String challengeComplete(int level, int timeLeft) {
		return String.format(//
				CHAL_TEXT + "[p][c5]challenge completed!" + //
						"[p][k][c]bonus [c2]10,000[c] awared!" + //
						"[p][c4]press jump", //
				level, timeLeft);
	}

	public static String challengeFailed(int level) {
		return String.format(//
				CHAL_TEXT + "[p][c1]challenge failed!" + //
						"[p][k][c]no bonus awarded" + //
						"[p][c4]press jump", //
				level);
	}
}
