package com.nney.tt;

public class PlayerVelocityTable {
	/**
	 * <code>true</code> to read {@link #VEL_NORM} <code>false</code> to read
	 * {@link #VEL_TURBO}.
	 * 
	 * <p>TODO: implement!
	 */
	private boolean plSprint;
	
	private static final int[] VEL_NORM = { 1, 3, 4, 5, 5, 5, 5, 5 };
	private static final int[] VEL_TURBO = { 1, 2, 3, 4, 6, 7, 9, 10 };

	/**
	 * Index into {@link #VEL_NORM} or {@link #VEL_TURBO}.
	 */
	private int velStep;

	private int lastDir;
	
	public int next(int dir) {
		if (dir!=lastDir) {
			velStep = 0;
			lastDir = dir;
		}
		int[] t = getTable();
		int answer = t[velStep];
		if (velStep != t.length - 1) velStep++;
		return answer*dir;
	}

	private int[] getTable() {
		return plSprint ? VEL_TURBO : VEL_NORM;
	}

	public int max() {
		int[] t = getTable();
		return t[t.length - 1];
	}
}
