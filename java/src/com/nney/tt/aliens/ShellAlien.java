package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;

public class ShellAlien extends AlienWithLocation {
	private Coord velocity;
	private boolean popping;

	public ShellAlien(Coord c, Coord velocity) {
		this.c = c;
		this.velocity = velocity;
	}

	@Override
	public void onLoaded() {
		changeAnimation(Anims.directionalAnimName(velocity.x < 0, ""));
	}

	@Override
	public void update() {
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (popping) {
			if (animPlayer.hasAnimEnded()) done();
		}
		else {
			if (srv.collideAlienWithPlayerHiRes(c, s)) {
				srv.getThePlayer().stun();
				pop();
			}
			c.add(velocity);
			if (srv.keepInMap(c) || srv.inTheGround(c)) pop();
		}
	}

	private void pop() {
		popping = true;
		changeAnimation("pop");
	}
}
