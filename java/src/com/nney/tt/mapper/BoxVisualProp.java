package com.nney.tt.mapper;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.World;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxVisualProp extends VisualProp<Box> {
	private static final int BORDER = 10;

	BoxVisualProp(PropPack pp) {
		super(pp);
	}
	
	@Override
	public Coord[] getBats() {
		Box t = read();
		return new Coord[] { location(), t.topLeft(), t.bottomRight(), t.topRight(), t.bottomLeft() };
	}
	
	@Override
	public void drawAuxBatStuff(BatGC rt) {
		Box t = read();
		rt.drawBox(t);
	}

	@Override
	void onBatMovement(int what, Coord where) {
		Box t = read();
		switch (what) {
		case 0:
			onBring(where);
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
		Box t = read();
		return String.format("x%dy%d w%dh%d", t.left, t.top, t.width(), t.height());
	}

	@Override
	void onBring(Coord c) {
		Box t = read();
		Coord delta = c.sub2(location());
		t.add(delta);
		validate();
	}


	@Override
	public void validate() {
		Box t = read();
		t.resideInside(World.WHOLE_MAP_BOUNDS_IN_PIXELS);
	}
	
	@Override
	public void moveBy(Coord delta) {
		Box t = read();
		t.add(delta);
	}


	@Override
	Coord location() {
		Box t = read();
		return t.middle();
	}
	
	@Override
	void save(DataDestination d) {
		Box t = read();
		t.save(d);
	}
	
	@Override
	void load(DataItem d) {
		write(Box.load(d));
	}
}
