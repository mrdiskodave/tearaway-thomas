package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class BirdAlien extends LeftRightAlien {
	@Override
	public void update() {
		moveLeftRight(2);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.headBounce(this, s, null);
		}
	}
}
