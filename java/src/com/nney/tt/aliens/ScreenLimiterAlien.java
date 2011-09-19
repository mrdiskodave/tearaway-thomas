package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class ScreenLimiterAlien extends AlienWithLocation {
	@AlienProp(name = "Inwards", doc = "A coordinate that tells us if we're limiting the left or right", label = "inwards")
	public Coord inwards;

	@Override
	public void loadFromLegacyData() {
		inwards = new Coord(loadShort(OBleft), loadShort(OBtop));
	}

	@Override
	public void update() {
		Box b = boxAroundUs(60);
		freezeBounds = b;
		boolean left = c.x<inwards.x;
		srv.screenLimit(c, left);
	}
	
	@Override
	public void mapperUpdate() {
		srv.drawDebugText(c, "Hidden Score");
	}
}
