package com.nney.tt.aliens;


public class ShieldAlien extends BonusAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveShield();
	}
}
