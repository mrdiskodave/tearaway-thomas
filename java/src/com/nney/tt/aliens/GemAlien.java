package com.nney.tt.aliens;

@AlienInfoAnns({
	@AlienInfoAnn(type = 80, gfx = "0frt0", score=100),
	@AlienInfoAnn(type = 81, gfx = "0frt1", score=200),
	@AlienInfoAnn(type = 82, gfx = "0frt2", score=300),
	@AlienInfoAnn(type = 83, gfx = "0frt3", score=400),
	@AlienInfoAnn(type = 84, gfx = "0frt4", score=500),
	@AlienInfoAnn(type = 85, gfx = "0frt5", score=600),
	@AlienInfoAnn(type = 86, gfx = "0hgem", score=2500),
	@AlienInfoAnn(type = 6, gfx = "0bgem", score=500)
})
public class GemAlien extends ScoreCollectableAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(ourValue(), scoreLocation());
	}
}
