package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public abstract class AbstractSimpleBonusAlien extends AbstractBonusAlien {
	@Override
	protected void normalUpdate() {
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (!isFalling()) freezeBounds = spriteBounds(s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			giveBonus();
			done();
		}
	}

	abstract protected void giveBonus();
}
