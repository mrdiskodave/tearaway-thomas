package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class FlameAlien extends AlienWithLocation {
	private int pause;

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		if (pause!=0) {
			pause--;
		}
		else {
			Sprite s = nextFrame();
			srv.drawSprite(c, s);
			if (srv.collideAlienWithPlayerHiRes(c, s)) {
				srv.getThePlayer().stun();
			}
			if (animPlayer.hasAnimEnded()) {
				animPlayer.rewind();
				pause = srv.randomness(64)+25;
			}
		}
		freezeBounds = anims.find(0).box().add2(c);
	}
}
