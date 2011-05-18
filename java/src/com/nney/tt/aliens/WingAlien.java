package com.nney.tt.aliens;

public class WingAlien extends BonusAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveWings();
	}
}
