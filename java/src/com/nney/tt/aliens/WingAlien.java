package com.nney.tt.aliens;

public class WingAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveWings();
	}
}
