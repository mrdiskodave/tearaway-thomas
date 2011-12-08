package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class EndZoneAlien extends Alien {
	@PropAnn(doc = "The objective the player much reach")
	public Box objectiveBox;

	@Override
	public void resetTo(Coord p) {
		objectiveBox = Box.around(p, 32, 60);
	}

	@Override
	public void loadFromLegacyData() {
		objectiveBox = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		boolean collide = objectiveBox.inside(srv.getPlayerPosition());
		if (collide) {
			srv.levelCompleted(null);
		}
	}

	@Override
	public Coord getLocation() {
		return objectiveBox.topLeft();
	}
}
