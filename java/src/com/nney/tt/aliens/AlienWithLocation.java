package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public abstract class AlienWithLocation extends Alien {
	@AlienProp(name = "Location", doc = "Where are we?", xtraDef = "location")
	public Coord c = new Coord();

	@Override
	public void resetTo(Coord p) {
		c = p;
	}

	protected Box spriteBounds(Sprite s) {
		Coord c = getLocation();
		return Box.fromTopLeftAndSize(c.x - s.handleX, c.y - s.handleY, s.w, s.h);
	}

	@Override
	public Coord getLocation() {
		return c;
	}
}
