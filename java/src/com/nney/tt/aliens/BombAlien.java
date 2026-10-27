package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

/**
 * A bomb dropped by a {@link BalloonAlien} (bomb_alien in s195). Drifts
 * sideways (slowing down), falls faster and faster up to 12 pixels a frame,
 * and explodes when it hits the ground. Stuns you if it lands on you.
 */
public class BombAlien extends AlienWithLocation {
	private static final int MAX_FALL = 12;

	private int vx;
	private int vy;
	private int slowTimer;
	private boolean exploding;

	public BombAlien(Coord where, int xVelocity) {
		this.c = where;
		this.vx = xVelocity;
	}

	@Override
	public void onLoaded() {
		changeAnimation("fall");
	}

	@Override
	public void update() {
		if (!exploding) move();

		Sprite s = nextFrame();
		srv.drawSprite(c, s);

		if (exploding) {
			if (animPlayer.hasAnimEnded()) done();
		}
		else if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
	}

	private void move() {
		// sideways drift dies away: one less every 5 frames
		if (++slowTimer >= 5) {
			slowTimer = 0;
			vx -= Integer.signum(vx);
		}
		c.x += vx;
		Coord probe = c.copy();
		if (srv.keepInMap(probe)) {
			done();
			return;
		}

		// fall a pixel at a time so we don't go through thin ground
		for (int n = 0; n < vy; n++) {
			c.y++;
			if (srv.inTheGround(c)) {
				explode();
				return;
			}
		}
		if ((srv.getFrameNumber() & 3) == 0 && vy < MAX_FALL) vy++;
	}

	private void explode() {
		exploding = true;
		changeAnimation("explode");
	}
}
