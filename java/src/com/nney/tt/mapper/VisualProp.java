package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

/**
 * A visual property. Current it just manages its control points. I'm typing
 * "bats" (as in "sports bats") throughout because "control point" is such a
 * mouthful.
 */
public abstract class VisualProp extends Prop {
	private Coord ourPosition;
	
	public VisualProp(AlienProp aprop, FieldAccessor fa) {
		super(aprop, fa);
	}
	
	@Override
	public void setPosition(Coord ourPosition) {
		this.ourPosition = ourPosition;
	}
	
	@Override
	String[] createButtons() {
		return new String[] { "find", "bring" };
	}
	
	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		switch (what) {
		case 0:
			// find
			bps.setScreenCentre(ourPosition);
			break;
		case 1:
			// bring
			onBring(bps.screenCentre());
			break;
		}
	}

	abstract void onBring(Coord c);
}