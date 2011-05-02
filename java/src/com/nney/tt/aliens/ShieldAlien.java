package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class ShieldAlien extends AbstractBonusAlien {
	@Override
	protected void normalUpdate() {
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().giveShield();
			done();
		}
	}
}
