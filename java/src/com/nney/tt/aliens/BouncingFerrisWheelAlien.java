package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class BouncingFerrisWheelAlien extends FerrisWheelAlien {
	@PropAnn(doc = "Box in which to bounce.")
	public Box bounceBox;

	@PropAnn(doc = "Speed to bounce left and right.")
	public int xspeed = 1;

	@PropAnn(doc = "Speed to bounce up and down.")
	public int yspeed = 1;

	private Box actualBounceBox;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		bounceBox = Box.around(p, 30);
	}

	/** Futureland's lifts were this wide (AGL table for Fferis_alien). */
	private static final int FUTURE_LIFT_WIDTH = 31;

	/**
	 * Futureland's wheel (Fferis_alien, future_feris in s195): radius 80, 8
	 * cars, one turn every 256 frames, and the whole wheel drifts 2 across and
	 * 3 down a frame, bouncing off the edges of a box (the box the original
	 * kept the centre within, which we grow by the radius).
	 */
	@Override
	public void loadFromLegacyData() {
		if (loadByte(OBtype) == 32) {
			int r = 80;
			int half = FUTURE_LIFT_WIDTH / 2;
			Coord centre = new Coord(3280 + half, 576);
			spinBox = Box.around(centre, r);
			spokes = 8;
			cycleLength = 256;
			xspeed = 2;
			yspeed = 3;
			Box centreBounds = new Box(3008 + r + half, 304 + r + 17, 3551 - r - 30 + half, 847 - r - 18);
			bounceBox = new Box(centreBounds.left - r, centreBounds.top - r, centreBounds.right + r,
					centreBounds.bottom + r);
		}
		else {
			super.loadFromLegacyData();
		}
	}

	@Override
	public void onPropUpdate() {
		super.onPropUpdate();
		actualBounceBox = bounceBox.copy();
		int w = spinBox.width() / 2;
		int h = spinBox.height() / 2;
		actualBounceBox.left += w;
		actualBounceBox.right -= w;
		actualBounceBox.top += h;
		actualBounceBox.bottom -= h;
	}

	@Override
	public void move() {
		super.move();
		centre.x += xspeed;
		centre.y += yspeed;
		if (!actualBounceBox.insideX(centre.x)) xspeed = -xspeed;
		if (!actualBounceBox.insideY(centre.y)) yspeed = -yspeed;
	}
}
