package com.nney.tt.aliens;

public class BigGemAlien extends AbstractSimpleBonusAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(500, c.copyAndMove(0, -15));
	}
	// TODO: ! bent class hierarchy doesn't group gems!
}
