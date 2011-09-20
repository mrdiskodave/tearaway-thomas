package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class SineLiftAlien extends LiftAlien {
	// need to think about what the props are here! could have signal generators
	// :O

	@AlienProp(name = "Box", doc = "The area we move within.", label = "box")
	public Box box;

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
		int angle = srv.getFrameNumber() * 8;
		Coord origin = new Coord((box.left + box.right) / 2, box.top);
		int spin = sine(angle) / 4 + 256;
		int xo = sine(spin + 256) * box.width();
		int yo = sine(spin) * box.height();
		xo /= 1024 * 2;
		yo /= 1024;
		return origin.copyAndAdd(xo, yo);
	}

}
