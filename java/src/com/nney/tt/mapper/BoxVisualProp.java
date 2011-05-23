package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxVisualProp extends VisualProp {
	private static final int BORDER = 10;
	private final Box t;

	BoxVisualProp(PropPack pp) {
		super(pp);
		this.t = (Box) pp.access().get();
	}

	@Override
	public Coord[] getBats(Coord alien) {
		return new Coord[] { t.middle(), t.topLeft(), t.bottomRight(), t.topRight(), t.bottomLeft() };
	}
	
	@Override
	public void drawAuxBatStuff(BatGC rt) {
		rt.drawBox(t);
	}

	@Override
	void onBatMovement(int what, Coord where) {
		switch (what) {
		case 0:
			where.sub(t.middle());
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
		return String.format("x%dy%d w%dh%d", t.left, t.top, t.width(), t.height());
	}

	@Override
	void onBring(Coord c) {
		Coord delta = t.middle();
		delta.sub(c);
		t.sub(delta);
	}
}
