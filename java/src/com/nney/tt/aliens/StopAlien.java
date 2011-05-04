package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class StopAlien extends Alien {
	private Box box;

	@Override
	public void load() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		Coord pp = srv.getPlayerPosition();
		boolean collide = box.inside(pp);
		if (collide) {
			if (c.x < pp.x) {
				pp.x = box.right;
			}
			else {
				pp.x = box.left;
			}
			System.out.println("Pushed by a StopAlien of width "+box.width());
		}
	}
}
