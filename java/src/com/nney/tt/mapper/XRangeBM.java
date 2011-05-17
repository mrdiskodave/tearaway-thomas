package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeBM extends BM {
	private final XRange t;

	public XRangeBM(XRange t) {
		this.t = t;
	}

	@Override
	public void sendBat(Coord alien, BatTarget rt) {
		Box box = new Box(t.left, Integer.MIN_VALUE/4, t.right, Integer.MAX_VALUE/4);
		rt.drawBox(box);
		rt.drawBat(new Coord(box.left, alien.y));
		rt.drawBat(new Coord(box.right, alien.y));
	}
	
	@Override
	void takeMovement(int what, Coord where) {
		assert what==0 || what==1;
		if (what==0) {
			t.left = where.x;
		}
		else {
			t.right = where.x;
		}
	}
}
