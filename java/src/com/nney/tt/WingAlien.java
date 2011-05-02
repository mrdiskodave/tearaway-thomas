package com.nney.tt;

import com.nney.tt.aliens.AbstractBonusAlien;
import com.nney.tt.sprites.Sprite;

public class WingAlien extends AbstractBonusAlien {
	@Override
	protected void normalUpdate() {
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().giveWings();
			done();
		}
	}
}
