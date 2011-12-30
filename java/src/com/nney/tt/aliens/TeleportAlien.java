package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

public class TeleportAlien extends AlienWithLocation {

	@PropAnn(doc = "Where do we teleport the player to?")
	public Coord destination;

	@PropAnn(doc = "Are we hidden from view?")
	public boolean hidden;

	private Box ourFreezeBounds;

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
	public void onLoaded() {
		changeAnimation(0);
		ourFreezeBounds = anims.getBounds();
		ourFreezeBounds.add(c);
	}

	@Override
	public void update() {
		if (!hidden) {
			Sprite s = nextFrame();
			srv.drawSprite(c, s);
		}
		freezeBounds = ourFreezeBounds;

		Box b = boxAroundUs(5);
		if (srv.collideBoxWithPlayer(b)) {
			// srv.drawDebugText(new Coord(10, 10), "hit");
			srv.teleportTo(destination);
		}
	}

}
