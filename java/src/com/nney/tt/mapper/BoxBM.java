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
		rt.drawBat(t.getMiddle());
		// 1
		rt.drawBat(t.getTopLeft());
		// 2
		rt.drawBat(t.getBottomRight());
		// 3
		rt.drawBat(t.getTopRight());
		// 4
		rt.drawBat(t.getBottomLeft());
	}

	@Override
	void moveTo(int what, Coord where) {
		switch (what) {
		case 0:
			where.sub(t.getMiddle());
			t.add(where);
			break;
		case 1:
			t.setLeft(where.x, BORDER);
			t.setTop(where.y, BORDER);
			break;
		case 2:
			t.setRight(where.x, BORDER);
			t.setBottom(where.y, BORDER);
			break;
		case 3:
			t.setRight(where.x, BORDER);
			t.setTop(where.y, BORDER);
			break;
		case 4:
			t.setLeft(where.x, BORDER);
			t.setBottom(where.y, BORDER);
			break;
		default:
			assert false;
		}
	}
	
	@Override
	public String text() {
		return String.format("%dx%d,%dx%d", t.left, t.top, t.right, t.bottom);
	}
}
