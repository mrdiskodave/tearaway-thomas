package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class PlainLiftAlien extends LiftAlien {
	// TODO: signal generators? :O

	@AlienProp(name = "Box", doc = "The area we move within.")
	public Box box;

	@Override
	public void resetTo(Coord c) {
		box = Box.around(c, 100, 20);
	}

	@Override
	protected Coord setPosition() {
		int frm = srv.getFrameNumber();

		int w = box.width();
		int h = box.height();
		boolean horizontalLift = w > h;
		if (horizontalLift) {
			int x = box.left + sawToothWave(frm, w - 1);
			int y = (box.top + box.bottom) / 2;
			return new Coord(x, y);
		}
		else {
			int x = (box.left + box.right) / 2;
			int y = box.top + sawToothWave(frm, h - 1);
			return new Coord(x, y);
		}
	}

	private int sawToothWave(int pos, int size) {
		pos %= size * 2;
		if (pos >= size) {
			pos = size * 2 - pos;
		}
		return pos;
	}
}
