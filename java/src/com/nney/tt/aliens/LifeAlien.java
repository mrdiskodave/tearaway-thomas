package com.nney.tt.aliens;

public class LifeAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.awardExtraLife();
	}
}
