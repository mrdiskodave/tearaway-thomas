package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

public class TeleportAlien extends AlienWithLocation {

	@PropAnn(name = "Destination", doc = "Where do we teleport the player to?", label = "destination")
	public Coord destination;
	
	@PropAnn(name = "Hidden", doc = "Are we hidden from view?", label = "hidden")
	public boolean hidden;
	
	@Override
	public void loadFromLegacyData() {
		destination = new Coord(loadShort(OBleft), loadShort(OBtop));
		hidden = Math2.bitTest(loadByte(OBflags), OBFinvis);
	}

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		destination = p.copyAndAdd(0, -40);
	}

	@Override
	public void update() {
		changeAnimation(0);
		if (!hidden) {
			Sprite s = nextFrame();
			srv.drawSprite(c, s);
		}

		Box b = boxAroundUs(5);
		freezeBounds = b;
		if (srv.collideBoxWithPlayer(b)) {
//			srv.drawDebugText(new Coord(10, 10), "hit");
			srv.teleportTo(destination);
		}
	}

}
