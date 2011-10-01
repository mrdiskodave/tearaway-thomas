package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

@AlienInfoAnns({
	@AlienInfoAnn(type = 80, gfx = "0frt0", score = 100, name = "fruit0" ),
	@AlienInfoAnn(type = 81, gfx = "0frt1", score = 200, name = "fruit1" ),
	@AlienInfoAnn(type = 82, gfx = "0frt2", score = 300, name = "fruit2" ),
	@AlienInfoAnn(type = 83, gfx = "0frt3", score = 400, name = "fruit3" ),
	@AlienInfoAnn(type = 84, gfx = "0frt4", score = 500, name = "fruit4" ),
	@AlienInfoAnn(type = 85, gfx = "0frt5", score = 600, name = "fruit5" ),
	@AlienInfoAnn(type = 62, gfx = "whone", score = 500, name = "fruit6" )
})
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
