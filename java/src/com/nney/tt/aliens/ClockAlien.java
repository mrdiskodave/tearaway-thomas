package com.nney.tt.aliens;

public class ClockAlien extends CollectableAlien {
	@Override
	protected void giveBonus() {
		srv.extraTime(5);
	}
}
