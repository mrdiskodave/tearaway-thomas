package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class BouncingFerrisWheelAlien extends FerrisWheelAlien {
	@PropAnn(doc = "Box in which to bounce.")
	public Box box;

	@PropAnn(doc = "Speed to bounce left and right.")
	public int xspeed = 1;

	@PropAnn(doc = "Speed to bounce up and down.")
	public int yspeed = 1;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(p, 30);
	}

	@Override
	public void move() {
		super.move();
		centre.x += xspeed;
		centre.y += yspeed;
		if (!box.insideX(centre.x)) xspeed = -xspeed;
		if (!box.insideY(centre.y)) yspeed = -yspeed;
	}
}
