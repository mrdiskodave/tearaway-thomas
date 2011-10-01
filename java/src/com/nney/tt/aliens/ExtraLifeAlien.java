package com.nney.tt.aliens;

public class ExtraLifeAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.awardExtraLife();
	}
}
