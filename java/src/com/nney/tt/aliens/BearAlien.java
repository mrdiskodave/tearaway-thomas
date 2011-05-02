package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class BearAlien extends LeftRightAlien {
	@Override
	public void update() {
		boolean turned = moveLeftRight(1);
		if (!srv.playerFall(c, 16)) {
			done();
		}
		if (!turned && srv.blockInfoIs(c, "stop")) {
			headedRight = !headedRight;
		}
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
	}
}
