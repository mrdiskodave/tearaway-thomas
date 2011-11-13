package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.tt.World;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeVisualProp extends VisualProp<XRange> {
	private static final int BORDER = 10;
	
	private static final int BAT_WIDTH = 3;

	public XRangeVisualProp(PropPack pp) {
		super(pp);
	}

	
	@Override
	public void getBats(List<Bat> bats) {
		bats.add(new Bat() {
			@Override
			public Box box() {
				XRange t = read();
				int x = t.middle();
				return new Box(x-BAT_WIDTH, 0, x+BAT_WIDTH, Integer.MAX_VALUE/2+1);
			}

			@Override
			public void onMove(Coord where) {
				onBring(where);
			}
		});


		bats.add(new Bat() {
			@Override
			public Box box() {
				XRange t = read();
				int x = t.left;
				return new Box(x-BAT_WIDTH, 0, x+BAT_WIDTH, Integer.MAX_VALUE/2+1);
			}

			@Override
			public void onMove(Coord where) {
				XRange t = read();
				t.setLeft(where.x, BORDER);
			}
		});

		bats.add(new Bat() {
			@Override
			public Box box() {
				XRange t = read();
				int x = t.right;
				return new Box(x-BAT_WIDTH, 0, x+BAT_WIDTH, Integer.MAX_VALUE/2+1);
			}

			@Override
			public void onMove(Coord where) {
				XRange t = read();
				t.setRight(where.x, BORDER);
			}
		});
	}
		
	@Override
	public void drawAuxBatStuff(VisualPropGC rt) {
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
	}

	@Override
	Coord location(Coord old) {
		XRange t = read();
		return new Coord(t.middle(), old.y);
	}

	@Override
	public void validate(Box constraints) {
		XRange t = read();
		t.resideInside(constraints.toXRange());
	}
	
	@Override
	public void moveBy(Coord delta) {
		XRange t = read();
		t.add(delta.x);
	}

	@Override
	void save(DataDestination d) {
		XRange t = read();
		t.save(d);
	}
	
	@Override
	void load(Node d) {
		write(XRange.load(d));
	}	
}
