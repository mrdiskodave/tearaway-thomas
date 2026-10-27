package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

/**
 * Futureland's hovering robot (r2d2_alien in s195): floats back and forth,
 * bobbing up and down. You can bounce on its head; touching it otherwise
 * stuns you.
 */
public class RobotAlien extends AlienWithLocation {
	/** ghost_sinewave in s195: 64 steps, +-16. */
	private static final int[] BOB = { 0, 1, 3, 4, 6, 7, 8, 10, 11, 12, 13, 14, 14, 15, 15, 15, 16, 15, 15, 15, 14,
			14, 13, 12, 11, 10, 8, 7, 6, 4, 3, 1, -1, -2, -4, -5, -7, -8, -9, -11, -12, -13, -14, -15, -15, -16, -16,
			-16, -16, -16, -16, -16, -15, -15, -14, -13, -12, -11, -9, -8, -7, -5, -4, -2 };

	@PropAnn(doc = "The span we float across.", label = "range")
	public XRange range;

	@PropAnn(doc = "Heading left?", label = "goLeft")
	public boolean goLeft;

	private int bobPhase;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		range = new XRange(p.x - 50, p.x + 50);
	}

	@Override
	public void loadFromLegacyData() {
		range = new XRange((short) loadShort(OBleft), (short) loadShort(OBright));
		goLeft = (loadByte(OBstatus0) & 1) == 0;
		bobPhase = loadByte(OBstatus1);
	}

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		// object_LR, 1 pixel a frame
		if (goLeft) {
			c.x--;
			if (c.x < range.left) goLeft = false;
		}
		else {
			c.x++;
			if (c.x > range.right) goLeft = true;
		}

		Coord drawAt = c.copyAndAdd(0, (BOB[bobPhase & 63] >> 1) - 16);
		bobPhase++;

		Sprite s = nextFrame();
		srv.drawSprite(drawAt, s);
		if (srv.collideAlienWithPlayerHiRes(drawAt, s)) {
			srv.headBounce(this, s);
		}
		freezeBounds = s.getBounds().add2(drawAt);
	}
}
