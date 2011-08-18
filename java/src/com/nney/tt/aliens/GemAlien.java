package com.nney.tt.aliens;

@AlienInfoAnns({
	@AlienInfoAnn(type = 86, gfx = "0hgem", score = 2500),
	@AlienInfoAnn(type = 6, gfx = "0bgem", score = 500)
})
public class GemAlien extends ScoreCollectableAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(ourValue(), scoreLocation());
//		srv.levelCompleted();
	}
}
