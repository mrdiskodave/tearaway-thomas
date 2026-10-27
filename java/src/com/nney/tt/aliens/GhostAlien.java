package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

/**
 * The ghosts are see-through. The Amiga drew them on every other frame (the
 * flicker blended on a 50Hz screen); we draw them at half opacity instead.
 */
public class GhostAlien extends LeftRightAlien {
	private static final float OPACITY = 0.5f;
	private static final int SINEWAVE_LENGTH = 64;
	static final private SineTable SINEWAVE = new SineTable(SINEWAVE_LENGTH, 16);
	private int sinePos;

	@Override
	public void onLoaded() {
		sinePos = c.pseudorandom(SINEWAVE_LENGTH, 500);
	}

	@Override
	public void update() {
		boolean turned = moveLeftRight(1);
		if (!srv.playerFall(c, 16)) {
			done();
		}
		if (!turned && srv.blockInfoIs(c, "stop")) {
			goLeft = !goLeft;
		}

		Coord c2 = c.copyAndAdd(0, SINEWAVE.get(sinePos) - 16);
		sinePos++;
		if (sinePos == SINEWAVE_LENGTH) sinePos = 0;

		animateDrawAndStun(c2, OPACITY);
	}
}
