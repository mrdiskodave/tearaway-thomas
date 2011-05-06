package com.nney.tt.aliens;


public class ShieldAlien extends AbstractSimpleBonusAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveShield();
	}
}
