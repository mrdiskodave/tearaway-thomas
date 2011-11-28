package com.nney.tt.aliens;

public class TurboAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveTurbo();
	}
}
