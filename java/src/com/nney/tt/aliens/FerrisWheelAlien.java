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
