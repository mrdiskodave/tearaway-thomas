package com.nney.tt.aliens;

public class HugeGemAlien extends AbstractSimpleBonusAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(2500, c.copyAndMove(0, -30));
	}
}
