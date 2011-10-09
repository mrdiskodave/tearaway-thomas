package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public class GhostAlien extends LeftRightAlien {
	private static final int SINEWAVE_LENGTH = 64;
	static final private SineTable SINEWAVE = new SineTable(SINEWAVE_LENGTH, 16);
	private int sinePos;

	@Override
	public void onLoaded() {
		sinePos = srv.randomness(c.slowHash(1000) % SINEWAVE_LENGTH);
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

		animateDrawAndStun(c2);
	}
}
