package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

@AlienInfoAnn(type = 62, gfx = "whone", score = 500)
public class ScoreCollectableAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.giveScore(ourValue(), scoreLocation());
	}

	protected Coord scoreLocation() {
		return c.copyAndAdd(0, sameFrame().h / -2);
	}

	protected int ourValue() {
		return alienInfo.score;
	}
}
