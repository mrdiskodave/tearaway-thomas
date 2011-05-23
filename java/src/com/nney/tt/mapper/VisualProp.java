package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

/**
 * A visual property. Current it just manages its control points. I'm typing
 * "bats" (as in "sports bats") throughout because "control point" is such a
 * mouthful.
 */
public abstract class VisualProp extends Prop {
	public VisualProp(PropPack pp) {
		super(pp);
	}
	
	private Coord location() {
		return getBats(alienPos())[0];
	}
	
	// TODO: moveBy (to be used as part of copy-alien)

	@Override
	String[] createButtons() {
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