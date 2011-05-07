package com.nney.tt.aliens;

public abstract class GemAlien extends BonusAlien {
	@Override
	protected void giveBonus() {
		srv.oneLessGem(ourValue(), c.copyAndMove(0, sameFrame().h / -2));
	}

	abstract protected int ourValue();
}
