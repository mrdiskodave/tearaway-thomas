package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public abstract class ScoreCollectableAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.giveScore(ourValue(), scoreLocation());
	}

	protected Coord scoreLocation() {
		return c.copyAndAdd(0, sameFrame().h / -2);
	}

	abstract protected int ourValue();
}
