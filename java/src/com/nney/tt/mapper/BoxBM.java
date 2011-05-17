package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxBM extends VisualProp {
	private static final int BORDER = 10;
	private final Box t;

	BoxBM(AlienProp p, Box t) {
		super(p);
		this.t = t;
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		rt.drawBox(t);
		// 0
		rt.drawBat(t.getTopLeft());
		// 1
		rt.drawBat(t.getBottomRight());
		// 2
		rt.drawBat(t.getTopRight());
		// 3
		rt.drawBat(t.getBottomLeft());
		// 4
		rt.drawBat(t.getMiddle());
	}

	@Override
	void takeBatMovement(int what, Coord where) {
		switch (what) {
		case 0:
			t.left = Math.min(t.right - BORDER, where.x);
			t.top = Math.min(t.bottom - BORDER, where.y);
			break;
		case 1:
			t.right = Math.max(t.left + BORDER, where.x);
			t.bottom = Math.max(t.right + BORDER, where.y);
			break;
		case 2:
			t.right = Math.max(t.left + BORDER, where.x);
			t.top = Math.min(t.bottom - BORDER, where.y);
			break;
		case 3:
			t.left = Math.min(t.right - BORDER, where.x);
			t.bottom = Math.max(t.right + BORDER, where.y);
			break;
		case 4:
			where.sub(t.getMiddle());
			t.add(where);
			break;
		default:
			assert false;
		}
	}
}
