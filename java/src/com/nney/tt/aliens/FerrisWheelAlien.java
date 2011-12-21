package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class FerrisWheelAlien extends LiftAlien {
	private static final int COUNT = 8;

	@PropAnn(doc = "Where are we?", label = "location")
	public Coord c = new Coord();

	@Override
	public void resetTo(Coord p) {
		c = p;
	}

	@Override
	public Coord getLocation() {
		return c;
	}

	@Override
	public void onPropUpdate() {
		dimension(COUNT);
	}

	@Override
	protected Coord[] currentPosition() {
		int radius = 50;
		int cycleLength = 50;

		Coord[] answer = new Coord[COUNT];
		for (int n = 0; n < COUNT; n++) {
			double angle = ((double) n) / COUNT;
			angle += ((double) (srv.getFrameNumber() % cycleLength)) / cycleLength;
			angle *= 2 * Math.PI;
			double x = Math.sin(angle) * radius;
			double y = Math.cos(angle) * radius;
			answer[n] = c.copyAndAdd((int) x, (int) y);
		}
		return answer;
	}
}
