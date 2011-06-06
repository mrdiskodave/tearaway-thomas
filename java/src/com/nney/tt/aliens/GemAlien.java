package com.nney.tt.aliens;

public abstract class GemAlien extends ScoreCollectableAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(ourValue(), scoreLocation());
	}
}
