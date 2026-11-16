package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public class ScoreCollectableAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.awardScore(ourValue(), scoreLocation());
	}

	/** The fruits: FXfruit (the same as FXgem) in s195. */
	@Override
	protected String soundEffect() {
		return "gem";
	}

	protected Coord scoreLocation() {
		return c.copyAndAdd(0, sameFrame().h / -2);
	}

	protected int ourValue() {
		return alienInfo.score;
	}
}
