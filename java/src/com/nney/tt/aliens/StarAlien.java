package com.nney.tt.aliens;

public class StarAlien extends BonusAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveStar();
	}
}
