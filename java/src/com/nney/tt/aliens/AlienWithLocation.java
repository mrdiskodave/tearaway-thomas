package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public abstract class AlienWithLocation extends Alien {
	@PropAnn(doc = "Where are we?", label = "location")
	public Coord c = new Coord();

	@Override
	public void resetTo(Coord p) {
		c = p;
	}

	@Override
	public Coord getLocation() {
		return c;
	}
}
