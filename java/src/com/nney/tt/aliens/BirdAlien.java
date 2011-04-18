package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class BirdAlien extends LeftRightAlien {
	@Override
	public void update() {
		moveLeftRight(2);
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			System.out.println("Bird GOTYA!");
		}
	}
}
