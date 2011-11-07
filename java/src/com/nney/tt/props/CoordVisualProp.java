package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.tt.World;
import com.nney.tt.geom.Coord;

public class CoordVisualProp extends VisualProp<Coord> {
	public CoordVisualProp(PropPack pp) {
		super(pp);
	}

	
	@Override
	public void getBats(List<Bat> bats) {
		bats.add(new PointBat() {
			@Override
			public Coord point() {
				return simpleLocation();
			}

			@Override
			public void onMove(Coord where) {
				onBring(where);
			}
		});
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
	Coord location(Coord old) {
		Coord t = read();
		return t.copy();
	}
	
	@Override
	void save(DataDestination d) {
		read().save(d);
	}
	
	@Override
	void load(Node d) {
		write(Coord.load(d));
	}
	
	@Override
	public void getButtons(List<Button> buttons, final ButtonPressServices bps) {
		super.getButtons(buttons, bps);
		buttons.add(new Button() {
			@Override
			public String name() {
				return "fall";
			}

			@Override
			public void press() {
				Coord c = read();
				bps.fall(c);
			}
		});
	}
	
	@Override
	public void validate() {
		World.WHOLE_MAP_BOUNDS_IN_PIXELS.constrain(read());
	}
}
