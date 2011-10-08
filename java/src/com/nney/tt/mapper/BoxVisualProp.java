package com.nney.tt.mapper;

import java.util.List;

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
	public void getBats(List<Bat> bats) {
		bats.add(new Bat() {
			@Override
			public Coord where() {
				return location();
			}

			@Override
			public void onMove(Coord where) {
				onBring(where);
			}
		});
		bats.add(new Bat() {
			@Override
			public Coord where() {
				Box t = read();
				return t.topLeft();
			}

			@Override
			public void onMove(Coord where) {
				Box t = read();
				t.setLeft(where.x, BORDER);
				t.setTop(where.y, BORDER);
			}
		});

		bats.add(new Bat() {
			@Override
			public Coord where() {
				Box t = read();
				return t.bottomRight();
			}

			@Override
			public void onMove(Coord where) {
				Box t = read();
				t.setRight(where.x, BORDER);
				t.setBottom(where.y, BORDER);
			}
		});

		bats.add(new Bat() {
			@Override
			public Coord where() {
				Box t = read();
				return t.topRight();
			}

			@Override
			public void onMove(Coord where) {
				Box t = read();
				t.setRight(where.x, BORDER);
				t.setTop(where.y, BORDER);
			}
		});

		bats.add(new Bat() {
			@Override
			public Coord where() {
				Box t = read();
				return t.bottomLeft();
			}

			@Override
			public void onMove(Coord where) {
				Box t = read();
				t.setLeft(where.x, BORDER);
				t.setBottom(where.y, BORDER);
			}
		});

	}

	@Override
	public void drawAuxBatStuff(BatGC rt) {
		Box t = read();
		rt.drawBox(t);
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
