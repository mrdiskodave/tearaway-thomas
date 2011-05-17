package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

/**
 * A visual property. Current it just manages its control points. I'm typing
 * "bats" (as in "sports bats") throughout because "control point" is such a
 * mouthful.
 */
public abstract class VisualProp extends Prop {
	public VisualProp(AlienProp prop) {
		super(prop);
	}

	abstract void createBats(Coord alien, BatTarget rt);

	abstract void takeBatMovement(int what, Coord where);
}