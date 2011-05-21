package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeVisualProp extends VisualProp {
	private static final int BORDER = 10;
	private final XRange t;

	public XRangeVisualProp(AlienProp p, FieldAccessor fa) {
		super(p, fa);
		this.t = (XRange) fa.get();
	}

	@Override
	public void createBats(BatTarget rt) {
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
		// 0
		rt.drawBat(t.middle());
		// 1
		rt.drawBat(t.left);
		// 2
		rt.drawBat(t.right);
	}

	@Override
	void onBatMovement(int what, Coord where) {
		switch (what) {
		case 0:
			t.add(where.x - t.middle());
			break;
		case 1:
			t.setLeft(where.x, BORDER);
			break;
		case 2:
			t.setRight(where.x, BORDER);
			break;
		default:
			assert false;
		}
	}

	@Override
	public String text() {
		return String.format("x%d w%d", t.left, t.width());
	}

	@Override
	void onBring(Coord c) {
		int delta = t.middle();
		delta -= c.x;
		t.sub(delta);
	}
}
