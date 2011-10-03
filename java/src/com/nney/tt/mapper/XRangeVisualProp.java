package com.nney.tt.mapper;

import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.World;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeVisualProp extends VisualProp<XRange> {
	private static final int BORDER = 10;

	public XRangeVisualProp(PropPack pp) {
		super(pp);
	}

	
	@Override
	public void getBats(List<Bat> bats) {
		bats.add(new Bat() {
			@Override
			Coord where() {
				return location();
			}

			@Override
			void onMove(Coord where) {
				onBring(where);
			}
		});


		bats.add(new Bat() {
			@Override
			Coord where() {
				XRange t = read();
				int apy = alienPos().y;
				return new Coord(t.left, apy);
			}

			@Override
			void onMove(Coord where) {
				XRange t = read();
				t.setLeft(where.x, BORDER);
			}
		});

		bats.add(new Bat() {
			@Override
			Coord where() {
				XRange t = read();
				int apy = alienPos().y;
				return new Coord(t.right, apy);
			}

			@Override
			void onMove(Coord where) {
				XRange t = read();
				t.setRight(where.x, BORDER);
			}
		});
	}
		
	@Override
	public void drawAuxBatStuff(BatGC rt) {
		XRange t = read();
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
	}

	@Override
	public String text() {
		XRange t = read();
		return String.format("x%d w%d", t.left, t.width());
	}

	@Override
	void onBring(Coord c) {
		XRange t = read();
		int delta = c.x;
		delta -= t.middle();
		t.add(delta);
		validate();
	}

	@Override
	public void validate() {
		XRange t = read();
		t.resideInside(World.WHOLE_MAP_BOUNDS_IN_PIXELS.toXRange());
	}
	
	@Override
	public void moveBy(Coord delta) {
		XRange t = read();
		t.add(delta.x);
	}

	@Override
	Coord location() {
		XRange t = read();
		int apy = alienPos().y;
		return new Coord(t.middle(), apy);
	}

	@Override
	void save(DataDestination d) {
		XRange t = read();
		t.save(d);
	}
	
	@Override
	void load(DataItem d) {
		write(XRange.load(d));
	}	
}
