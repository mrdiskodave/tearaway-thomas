package com.nney.tt.aliens;

/**
 * The honey pot (hone_alien in s195): scores like a fruit, but sounds like
 * the other power-ups (FXcollect), not like a fruit.
 */
public class HoneyAlien extends ScoreCollectableAlien {
	@Override
	protected String soundEffect() {
		return "collect";
	}
}
