package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class GhostAlien extends LeftRightAlien {
	private static final int SINE_LENGTH = 64;
	static final private SineTable GHOST_SINE = new SineTable(SINE_LENGTH, 16);
	private int sinePos;
	
	@Override
	public void visualReset() {
		sinePos = srv.randomness(SINE_LENGTH);
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
		Sprite s = nextFrame();
		
		Coord c2 = c.copyAndAdd(0, GHOST_SINE.get(sinePos++)-16);
		if (sinePos==SINE_LENGTH) sinePos=0;
		
		srv.drawSprite(c2, s);
		if (srv.collideAlienWithPlayerHiRes(c2, s)) {
			srv.getThePlayer().stun();
		}
	}
}
