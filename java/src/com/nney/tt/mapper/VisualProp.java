package com.nney.tt.mapper;

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
	
	abstract Coord location();
	
	@Override
	String[] getButtons() {
		return new String[] { "find", "bring" };
	}
	
	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		switch (what) {
		case 0:
			// find
			bps.setScreenCentre(location());
			break;
		case 1:
			// bring
			onBring(bps.screenCentre());
			break;
		}
	}

	abstract void onBring(Coord c);
}