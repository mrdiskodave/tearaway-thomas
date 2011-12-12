package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.utils.Math2;

public class SineLiftAlien extends LiftAlien {
	@PropAnn(doc = "The area we move within.")
	public Box box;

	@PropAnn(doc = "Our movement in relation to other lifts (0-99)")
	public int phase;

	@Override
	public void resetTo(Coord c) {
		box = Box.around(c, 100, 100);
	}

	@Override
	public void loadFromLegacyData() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	static int sine(int idx) {
		int maxInput = 1024;
		int maxOutput = 1024;
		idx &= maxInput - 1;
		double angle = (2 * Math.PI * idx) / maxInput;
		return (int) (Math.sin(angle) * maxOutput);
	}

	@Override
	protected Coord currentPosition() {
		int f = srv.getFrameNumber() + Math2.percent2(128, phase);
		int angle = (f % 128) * 8;
		Coord origin = new Coord((box.left + box.right) / 2, box.top);
		int spin = sine(angle) / 4 + 256;
		int xo = sine(spin + 256) * box.width();
		int yo = sine(spin) * box.height();
		xo /= 1024 * 2;
		yo /= 1024;
		return origin.copyAndAdd(xo, yo);
	}

}
