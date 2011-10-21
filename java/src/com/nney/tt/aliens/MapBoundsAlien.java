package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class MapBoundsAlien extends Alien {
	@PropAnn(name = "Bounds", doc = "Where is the player is allowed to roam?", label = "bounds")
	public Box bounds;

	@Override
	public void resetTo(Coord p) {
		bounds = Box.around(p, 32);
	}

	// TODO: snap to grid in Mapper....? :O

	@Override
	public Coord getLocation() {
		return bounds.topLeft();
	}

	@Override
	public void update() {
		freezeBounds = Box.around(getLocation());
	}
}
