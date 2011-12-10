package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public class ScoreCollectableAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.awardScore(ourValue(), scoreLocation());
	}

	protected Coord scoreLocation() {
		return c.copyAndAdd(0, sameFrame().h / -2);
	}

	protected int ourValue() {
		return alienInfo.score;
	}
}
