package com.nney.tt.aliens;


public class WingAlien extends AbstractSimpleBonusAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveWings();
	}
}
