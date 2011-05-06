package com.nney.tt.aliens;

public class StarAlien extends AbstractSimpleBonusAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveStar();
	}
}
