package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class FerrisWheelAlien extends LiftAlien {
	private static final int COUNT = 8;

	@PropAnn(doc = "What is our centre?")
	public Coord centre = new Coord();

	@PropAnn(doc = "What is our radius in pixels?", min = 1)
	int radius = 50;

	@PropAnn(doc = "How many frames does one revolution take?", min = 10)
	int cycleLength = 200;

	@Override
	public void resetTo(Coord p) {
		centre = p;
	}

	@Override
	public Coord getLocation() {
		return centre;
	}

	@Override
	public void onPropUpdate() {
		dimension(COUNT);
	}

	@Override
	protected Coord[] currentPosition() {
		Coord[] answer = new Coord[COUNT];
		for (int n = 0; n < COUNT; n++) {
			double angle = n;
			angle /= COUNT;

			double where = srv.getFrameNumber() % cycleLength;
			angle += where / cycleLength;

			angle *= 2 * Math.PI;
			double x = Math.sin(angle) * radius;
			double y = Math.cos(angle) * radius;
			answer[n] = centre.copyAndAdd((int) x, (int) y);
		}
		return answer;
	}
}
