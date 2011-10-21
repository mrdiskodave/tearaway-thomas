package com.nney.tt.props;

import java.util.List;

import com.nney.tt.geom.Coord;

/**
 * A visual property. It provides control points to manipulate the property. I'm
 * typing "bats" throughout (bat as in "sports bat") because "control point" is
 * such a mouthful.
 */
public abstract class VisualProp<T> extends SpecificProp<T> {
	public VisualProp(PropPack pp) {
		super(pp);
	}

	abstract Coord location(Coord old);

	public Coord simpleLocation() {
		return location(null);
	}

	@Override
	public void getButtons(List<Button> buttons, final ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			public String name() {
				return "find";
			}

			@Override
			public void press() {
				bps.setScreenCentre(location(bps.screenCentre()));
			}
		});
		buttons.add(new Button() {
			@Override
			public String name() {
				return "bring";
			}

			@Override
			public void press() {
				onBring(bps.screenCentre());
			}
		});
	}

	abstract void onBring(Coord c);
}