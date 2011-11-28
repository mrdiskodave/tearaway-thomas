package com.nney.tt;

public class PlayerVelocityTable {
	private static final int[] VEL_NORM = { 1, 3, 4, 5, 5, 5, 5, 5 };
	private static final int[] VEL_TURBO = { 1, 2, 3, 4, 6, 7, 9, 10 };

	/**
	 * Index into {@link #VEL_NORM} or {@link #VEL_TURBO}.
	 */
	private int velStep;

	private int lastDir;
	private boolean sprint;

	public void setSprint(boolean s) {
		sprint = s;
	}

	public int next(int dir) {
		if (dir != lastDir) {
			velStep = 0;
			lastDir = dir;
		}
		int[] t = sprint ? VEL_TURBO : VEL_NORM;
		int answer = t[velStep];
		if (velStep != t.length - 1) velStep++;
		return answer * dir;
	}

	public int max() {
		int[] t = (sprint ? VEL_TURBO : VEL_NORM);
		return t[t.length - 1];
	}
}
