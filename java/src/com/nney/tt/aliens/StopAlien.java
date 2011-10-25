package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class StopAlien extends AlienWithLocation {
	@PropAnn(doc = "The area we shove the player out of!")
	public Box pushBox;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		pushBox = Box.around(c, 32, 60);
		pushBox.add(new Coord(40, 0));
	}

	@Override
	public void loadFromLegacyData() {
		pushBox = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		Coord pp = srv.getPlayerPosition();
		boolean collide = pushBox.inside(pp);
		if (collide) {
			if (c.x < pp.x) {
				pp.x = pushBox.right + 1;
			}
			else {
				pp.x = pushBox.left - 1;
			}
			System.out.println("Pushed by a StopAlien of width " + pushBox.width());
		}
	}
}
