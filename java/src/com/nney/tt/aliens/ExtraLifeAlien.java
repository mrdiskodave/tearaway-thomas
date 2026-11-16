package com.nney.tt.aliens;

public class ExtraLifeAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.awardExtraLife();
	}

	/** FXbgem (life_alien in s195). */
	@Override
	protected String soundEffect() {
		return "bigGem";
	}
}
