package com.nney.tt.mapper;

import com.nney.tt.MapperServices;
import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

/**
 * A visual property. Current it just manages its control points. I'm typing
 * "bats" (as in "sports bats") throughout because "control point" is such a
 * mouthful.
 */
public abstract class VisualProp extends Prop {
	Coord showMe;
	
	public VisualProp(AlienProp aprop) {
		super(aprop);
	}

	abstract void createBats(Coord alien, BatTarget rt);

	abstract void moveTo(int what, Coord where);
	
	void click(MapperServices srv) {}
}