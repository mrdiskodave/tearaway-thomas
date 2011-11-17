package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class CarAlien extends LeftRightAlien {
	@Override
	public void update() {
		moveLeftRight(getSpeed());
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			if (srv.headBounce(this, s)) {
				if (anims.mightFind("fright")!=null) {
					movingFright = 32;
				}
			}
		}
	}

	protected int getSpeed() {
		return 1;
	}
}
