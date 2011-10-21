package com.nney.tt.mapper;

import java.util.List;

import com.nney.tt.geom.Coord;

/**
 * A visual property. Current it just manages its control points. I'm typing
 * "bats" (as in "sports bats") throughout because "control point" is such a
 * mouthful.
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
	void getButtons(List<Button> buttons, final ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			String name() {
				return "find";
			}

			@Override
			void press() {
				bps.setScreenCentre(location(bps.screenCentre()));
			}
		});
		buttons.add(new Button() {
			@Override
			String name() {
				return "bring";
			}

			@Override
			void press() {
				onBring(bps.screenCentre());
			}
		});
	}

	abstract void onBring(Coord c);
}