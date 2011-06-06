package com.nney.tt.aliens;

public class StarAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveStar();
	}
}
