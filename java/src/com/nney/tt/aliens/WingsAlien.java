package com.nney.tt.aliens;

public class WingsAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveWings();
	}
}
