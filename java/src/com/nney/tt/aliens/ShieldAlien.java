package com.nney.tt.aliens;

public class ShieldAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.getThePlayer().giveShield();
	}
}
