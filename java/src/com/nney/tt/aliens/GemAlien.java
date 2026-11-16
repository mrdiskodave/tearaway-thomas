package com.nney.tt.aliens;

public class GemAlien extends ScoreCollectableAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(ourValue(), scoreLocation());
		// srv.levelCompleted();
	}

	/** The big and huge gems: FXbgem (bgem_alien, hgem_alien in s195). */
	@Override
	protected String soundEffect() {
		return "bigGem";
	}
}
