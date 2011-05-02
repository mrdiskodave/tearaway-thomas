package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class GemAlien extends AbstractBonusAlien {
	private static final int FLAG_NO_WOBBLE = 3;

	private static final int[] WOBBLE = { 0, -1, -2, -3, -2, -1, 0, 1, 2, 3, 2, 1 };

	private boolean wobble;
	private int wobblePhase;
	private int scoreTimer;
	private int scoreFrame;

	@Override
	public void load() {
		super.load();
		wobble = !BitOp.test(loadByte(OBflags), FLAG_NO_WOBBLE);
	}

	@Override
	public void init() {
		super.init();
		wobblePhase = srv.randomness(WOBBLE.length);
	}

	@Override
	protected void normalUpdate() {
		if (scoreTimer != 0) {
			changeAnimation(scoreFrame);
			srv.queueSprite(c, nextFrame());
			if (--scoreTimer==0) {
				done();
			}
		}
		else {
			Coord c2 = c.copy();
			if (wobble && !isFalling()) {
				c2.y += WOBBLE[wobblePhase++];
				wobblePhase %= WOBBLE.length;
			}
			Sprite s = nextFrame();
			srv.queueSprite(c2, s);

			if (srv.collideAlienWithPlayerHiRes(c2, s)) {
				scoreTimer = 25;
				scoreFrame = 1;
			}

			if (!isFalling()) {
				freezeBounds = Box.around(c, 20, 20);
			}
		}
	}

}
