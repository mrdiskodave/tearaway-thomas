package com.nney.tt.aliens;

public class GemAlien extends ScoreCollectableAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(ourValue(), scoreLocation());
		// srv.levelCompleted();
	}
}
