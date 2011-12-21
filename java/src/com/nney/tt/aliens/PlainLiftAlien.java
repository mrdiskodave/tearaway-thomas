package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class PlainLiftAlien extends LiftAlien {
	@PropAnn(doc = "Where the lift starts from")
	public Coord start;

	@PropAnn(doc = "Where the lift ends up")
	public Coord end;

	@PropAnn(doc = "Our movement in relation to other identical things (0-99)")
	public int phase;

	@PropAnn(doc = "How long do we wait at either end?")
	public int pause;

	@Override
	public void resetTo(Coord c) {
		start = c.copyAndAdd(50, 0);
		end = c.copyAndAdd(-50, 0);
		phase = 0;
		pause = 50;
	}

	@Override
	protected Coord[] currentPosition() {
		Coord delta = end.sub2(start);
		Coord absDelta = new Coord(Math.abs(delta.x), Math.abs(delta.y));

		boolean majorX = absDelta.x > absDelta.y;
		int big = majorX ? absDelta.x : absDelta.y;

		int pos = Wave.sawToothWaveWithPauseAndPhase(big, pause, phase, srv.getFrameNumber()).pos;
		float frac = pos;
		frac /= big;
		if (majorX) {
			delta.x = pos * Integer.signum(delta.x);
			delta.y = Math.round(delta.y * frac);
		}
		else {
			delta.x = Math.round(delta.x * frac);
			delta.y = pos * Integer.signum(delta.y);
		}

		delta.add(start);
		return new Coord[] { delta };
	}
}
