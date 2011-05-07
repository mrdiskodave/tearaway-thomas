package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public abstract class BonusAlien extends HiddenAlien {
	@Override
	protected void normalUpdate() {
		Sprite s = sameFrame();
		srv.drawSprite(c, s);
		if (!isFalling()) freezeBounds = spriteBounds(s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			giveBonus();
			done();
		}
	}

	abstract protected void giveBonus();
}
