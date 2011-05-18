package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class StunSpriteAlien extends Alien {

	@Override
	public void visualReset() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		Sprite s = sameFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();

			// TODO: 30: not quite as simple as that!
			// see 'rflm_alien'
			// they have variable delays on the end
			// and the flame probably does need a custom
			// Collision box (or at least to only
			// collide on certain frames!)

		}
	}

}
