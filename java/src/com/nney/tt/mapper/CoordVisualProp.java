package com.nney.tt.mapper;

import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.geom.Coord;

public class CoordVisualProp extends VisualProp<Coord> {
	public CoordVisualProp(PropPack pp) {
		super(pp);
	}

	@Override
	public Coord[] getBats() {
		return new Coord[] { location() };
	}

	@Override
	void onBatMovement(int what, Coord where) {
		assert what == 0;
		onBring(where);
	}
	

	@Override
	void onBring(Coord c) {
		write(c.copy());
	}

	@Override
	public void moveBy(Coord delta) {
		Coord t = read();
		t.add(delta);
	}

	@Override
	public String text() {
		Coord t = read();
		return String.format("x%dy%d", t.x, t.y);
	}

	@Override
	Coord location() {
		Coord t = read();
		return t.copy();
	}
	
	@Override
	void save(DataDestination d) {
		read().save(d);
	}
	
	@Override
	void load(DataItem d) {
		write(Coord.load(d));
	}
	
	@Override
	void getButtons(List<Button> buttons, final ButtonPressServices bps) {
		super.getButtons(buttons, bps);
		buttons.add(new Button() {
			@Override
			String name() {
				return "fall";
			}

			@Override
			void press() {
				Coord c = read().copy();
				if (bps.playerFall(c, 64)) {
					write(c);
				}
			}
		});
	}
}
