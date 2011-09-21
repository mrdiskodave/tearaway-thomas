package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class MapBoundsAlien extends Alien {
	@AlienProp(name = "Bounds", doc = "Where is the player is allowed to roam?", label = "bounds")
	public Box bounds;

	@Override
	public void resetTo(Coord p) {
		bounds = Box.around(p, 32);
	}
	
	@Override
	public void onPropUpdate() {
//		bounds = Box.fromTopLeftAndSize(snap(bounds.left), snap(bounds.top), snap(bounds.width()), snap(bounds.height()));
	}
	
	private int snap(int x) {
		x &= -16;
		return x;
	}

	@Override
	public Coord getLocation() {
		return bounds.topLeft();
	}

	@Override
	public void update() {
		
	}
	
	@Override
	public void mapperUpdate() {
		srv.drawDebugText(getLocation().add2(new Coord(1,1)), "MapBounds");
	}

}
