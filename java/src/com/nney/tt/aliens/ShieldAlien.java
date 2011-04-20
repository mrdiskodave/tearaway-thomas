package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class ShieldAlien extends Alien {
	
	@Override
	public void init() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().giveShield();
			remove = true;
		}
		// TODO: AAA invisi control?
	}
}
