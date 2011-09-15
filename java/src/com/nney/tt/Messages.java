package com.nney.tt;

public class Messages {
	public static String levelStart(int world, int stage, String name, int gemsRequired, int gemsAvailable, int time) {
		return String.format(//
				"[c1]world %s[n][c2]stage %d[p][c5]<%s>" + //
						"[p][t2,3][hp30]" + //
						"[c0]gems required[e][c4]%d[e]" + //
						"[c0]gems on level[e][c4]%d[e]" + //
						"[c0]time[e][c4]%d[e]" + //
						"[p][c5]good luck![p][c4]press jump", //
				world, stage, name, gemsRequired, gemsAvailable, time);
	}

	public static String levelComplete(int world, int stage, String name, int gemsCollected, int gemsRemaining,
			int timeLeft, boolean starSkip) {
		String t = String.format(//
				"[c1]world %s[n][c2]stage %d[p][c5]stage completed!" + //
						"[p][t2,3][hp30]" + //
						"[c0]gems collected[e][c4]%d[e]" + //
						"[c0]gems remaining[e][c4]%d[e]" + //
						"[c0]time left[e][c4]%d[e]", world, stage, gemsCollected, gemsRemaining, timeLeft);
		
		if (gemsRemaining==0 || starSkip) {
			t += "[p]";
		}
		if (gemsRemaining==0) {
			t += "[c5][k4]perfect gem collection![k0][n]";
		}
		if (starSkip) {
			t += "[c5][k4]star skip collected![k0][n]";
		}
		
		t += "[p][c4]press jump";
		
		return t;
	}
}
