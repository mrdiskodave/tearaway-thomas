package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class FerrisWheelAlien extends LiftAlien {

	@PropAnn(doc = "How many spokes do we have?", min = 1, max = 50)
	public int spokes = 4;

	@PropAnn(doc = "What is our centre?")
	public Coord centre = new Coord();

	@PropAnn(doc = "Any point on our edge (to define the radius).", min = 1)
	public Coord edge;

	@PropAnn(doc = "How many frames does one revolution take?", min = 10)
	public int cycleLength = 200;

	private int radius;

	@Override
	public void resetTo(Coord p) {
		centre = p.copy();
		edge = p.copyAndAdd(50, 0);
	}

	@Override
	public Coord getLocation() {
		return centre;
	}

	@Override
	public void onPropUpdate() {
		radius = centre.sub2(edge).length();
		dimension(spokes);
	}

	@Override
	protected Coord[] currentPosition() {
		Coord[] answer = new Coord[spokes];
		for (int n = 0; n < spokes; n++) {
			double angle = n;
			angle /= spokes;

			double where = srv.getFrameNumber() % cycleLength;
			angle += where / cycleLength;

			angle *= 2 * Math.PI;
			double x = Math.round(Math.sin(angle) * radius);
			double y = Math.round(Math.cos(angle) * radius);
			answer[n] = centre.copyAndAdd((int) x, (int) y);
		}
		return answer;
	}
}
