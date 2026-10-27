package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class FerrisWheelAlien extends LiftAlien {

	@PropAnn(doc = "How many spokes do we have?", min = 1, max = 50)
	public int spokes = 4;

	@PropAnn(doc = "The box in which we spin.")
	public Box spinBox;

	@PropAnn(doc = "How many frames does one revolution take?", min = 10)
	public int cycleLength = 200;

	public Coord centre;

	@Override
	public void resetTo(Coord p) {
		spinBox = Box.around(p, 50);
	}

	/** The original's lifts were this wide (AGL table); our centre is mid-lift. */
	private static final int ICE_LIFT_WIDTH = 36;

	/**
	 * The original had one object per car (feris_alien in s195), all sharing a
	 * wheel described in a table (ice_feris). We're the whole wheel, so the
	 * map upgrade keeps the first car and drops the rest.
	 * 
	 * Ice: centre (2240, 1104), radius 256, 8 cars, angle (0-255) going up by
	 * one a frame, x = sin and y = cos: exactly what we do already.
	 */
	@Override
	public void loadFromLegacyData() {
		int type = loadByte(OBtype);
		if (type == 44) {
			Coord centre = new Coord(2240 + ICE_LIFT_WIDTH / 2, 1104);
			spinBox = Box.around(centre, 256);
			spokes = 8;
			cycleLength = 256;
		}
	}

	@Override
	public Coord getLocation() {
		return spinBox.centre();
	}

	@Override
	public void onPropUpdate() {
		dimension(spokes);
		centre = spinBox.centre();
	}

	@Override
	protected Coord[] currentPosition() {
		int wRadius = spinBox.width() / 2;
		int hRadius = spinBox.height() / 2;

		Coord[] answer = new Coord[spokes];
		for (int n = 0; n < spokes; n++) {
			double angle = n;
			angle /= spokes;

			double where = srv.getFrameNumber() % cycleLength;
			angle += where / cycleLength;

			angle *= 2 * Math.PI;
			double x = Math.round(Math.sin(angle) * wRadius);
			double y = Math.round(Math.cos(angle) * hRadius);
			answer[n] = centre.copyAndAdd((int) x, (int) y);
		}
		return answer;
	}
}
