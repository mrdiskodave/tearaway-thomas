package com.nney.tt.aliens;

import com.nney.tt.AlienMovementServices;
import com.nney.tt.BitOp;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class GemAlien extends Alien {
	private static final int FLAG_NO_WOBBLE = 3;

	private static final int[] WOBBLE = { 0, -1, -2, -3, -2, -1, 0, 1, 2, 3, 2, 1 };

	private boolean wobble;
	private int wobblePhase = -1;

	@Override
	public void load() {
		wobble = !BitOp.test(loadByte(OBflags), FLAG_NO_WOBBLE);
		wobble = false;
	}

	@Override
	public void init() {
		changeAnimation(0);
	}

	@Override
	public void draw(AlienMovementServices ads) {
		if (wobblePhase < 0) {
			// could we do this earlier? (pass that arg to init??)
			wobblePhase = ads.randomness(WOBBLE.length);
		}
		Coord c2 = new Coord(c);

		// this is what gem_render -> bob_gem does
		c2.x += 8;

		if (wobble) {
			c2.y += WOBBLE[wobblePhase++];
			wobblePhase %= WOBBLE.length;
		}
		Sprite s = animPlayer.next();
		ads.queueSprite(c2, s);
		ads.col2(s, c2);
	}
}
