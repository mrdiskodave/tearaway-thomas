package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeBM extends VisualProp {
	private final XRange t;

	public XRangeBM(AlienProp p, XRange t) {
		super(p);
		this.t = t;
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
		// 0
		rt.drawBat(new Coord(box.left, alien.y));
		// 1
		rt.drawBat(new Coord(box.right, alien.y));
	}

	@Override
	void takeBatMovement(int what, Coord where) {
		switch (what) {
		case 0:
			t.left = Math.min(t.right - 10, where.x);
			break;
		case 1:
			t.right = Math.max(t.left + 10, where.x);
			break;
		default:
			assert false;
		}
	}
}
