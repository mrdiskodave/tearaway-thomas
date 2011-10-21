package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

public abstract class AlienWithLocation extends Alien {
	@PropAnn(name = "Location", doc = "Where are we?", label = "location")
	public Coord c = new Coord();

	@Override
	public void resetTo(Coord p) {
		c = p;
	}
	

	protected Box spriteBounds(Sprite s) {
		return s.box().add2(c);
	}
	
	protected Box boxAroundUs(int size) {
		return Box.around(c, size);
	}

	@Override
	public Coord getLocation() {
		return c;
	}
}
