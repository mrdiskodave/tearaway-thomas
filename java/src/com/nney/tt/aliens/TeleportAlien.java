package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class TeleportAlien extends AlienWithLocation {
	@AlienProp(name = "Destination", doc = "Where do we teleport the player to?")
	public Coord destination;

	@Override
	public void loadFromLegacyData() {
		destination = new Coord(loadShort(OBleft), loadShort(OBtop));
	}

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		destination = p.copyAndAdd(0, -100);
	}

	@Override
	public void update() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);

		if (srv.collideBoxWithPlayer(c, Box.fromSquare(5))) {
			srv.drawDebugText(new Coord(10, 10), "hit");
			srv.teleportTo(destination);
		}
	}

}
