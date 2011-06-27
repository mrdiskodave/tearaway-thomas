package com.nney.tt.mapper;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.World;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxVisualProp extends VisualProp {
	private static final int BORDER = 10;
	private final Box t;

	BoxVisualProp(PropPack pp) {
		super(pp);
		this.t = (Box) pp.access().get();
		assert t!=null;
	}

	
	@Override
	public Coord[] getBats() {
		return new Coord[] { location(), t.topLeft(), t.bottomRight(), t.topRight(), t.bottomLeft() };
	}
	
	@Override
	public void drawAuxBatStuff(BatGC rt) {
		rt.drawBox(t);
	}

	@Override
	void onBatMovement(int what, Coord where) {
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
		return String.format("x%dy%d w%dh%d", t.left, t.top, t.width(), t.height());
	}

	@Override
	void onBring(Coord c) {
		Coord delta = c.sub2(location());
		t.add(delta);
		validate();
	}


	@Override
	public void validate() {
		t.resideInside(World.WHOLE_MAP_BOUNDS_IN_PIXELS);
	}
	
	@Override
	public void moveBy(Coord delta) {
		t.add(delta);
	}


	@Override
	Coord location() {
		return t.middle();
	}
	
	@Override
	void save(DataDestination d) {
		d.beginArray();
		d.write(t.left);
		d.write(t.top);
		d.write(t.right);
		d.write(t.bottom);
		d.end();
	}
	
	@Override
	void load(DataItem d) {
		t.left = d.requireElement(0).requireInt();
		t.top = d.requireElement(1).requireInt();
		t.right = d.requireElement(2).requireInt();
		t.bottom = d.requireElement(3).requireInt();
	}
}
