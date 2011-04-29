package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class GemAlien extends Alien {
	private static final int FLAG_NO_WOBBLE = 3;

	private static final int[] WOBBLE = { 0, -1, -2, -3, -2, -1, 0, 1, 2, 3, 2, 1 };

	private boolean wobble;
	private int wobblePhase = -1;

	private int scoreTimer;

	private int scoreFrame;

	@Override
	public void load() {
		wobble = !BitOp.test(loadByte(OBflags), FLAG_NO_WOBBLE);
	}

	@Override
	public void init() {
		changeAnimation(0);
		wobblePhase = srv.randomness(WOBBLE.length);
	}

	@Override
	public void update() {
		Coord c2 = c.copy();
		
		if (scoreTimer != 0) {
			changeAnimation(scoreFrame);
			srv.queueSprite(c2, nextFrame());
			if (--scoreTimer==0) {
				remove = true;
			}
		}
		else {
			if (wobble) {
				c2.y += WOBBLE[wobblePhase++];
				wobblePhase %= WOBBLE.length;
			}
			Sprite s = nextFrame();
			srv.queueSprite(c2, s);
			if (srv.collideAlienWithPlayerHiRes(c2, s)) {
				scoreTimer = 25;
				scoreFrame = 1;
			}

			freezeBounds = new Box(c.x-20, c.y-20, c.x+20, c.y+20);
		}
	}
}
