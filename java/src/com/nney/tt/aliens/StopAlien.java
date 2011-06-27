package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class StopAlien extends AlienWithLocation {
	@AlienProp(name = "PushBox", doc = "The area we shove the player out of!", label = "pushBox")
	public Box box;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(c, 32, 60);
		box.add(new Coord(40, 0));
	}

	@Override
	public void loadFromLegacyData() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		Coord pp = srv.getPlayerPosition();
		boolean collide = box.inside(pp);
		if (collide) {
			if (c.x < pp.x) {
				pp.x = box.right + 1;
			}
			else {
				pp.x = box.left - 1;
			}
			System.out.println("Pushed by a StopAlien of width " + box.width());
		}
	}
}
