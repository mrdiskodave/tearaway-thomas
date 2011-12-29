package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class BouncingFerrisWheelAlien extends FerrisWheelAlien {
	@PropAnn(doc = "Box in which to bounce.")
	public Box bounceBox;

	@PropAnn(doc = "Speed to bounce left and right.")
	public int xspeed = 1;

	@PropAnn(doc = "Speed to bounce up and down.")
	public int yspeed = 1;

	private Box actualBounceBox;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		bounceBox = Box.around(p, 30);
	}

	@Override
	public void onPropUpdate() {
		super.onPropUpdate();
		actualBounceBox = bounceBox.copy();
		int w = spinBox.width() / 2;
		int h = spinBox.height() / 2;
		actualBounceBox.left += w;
		actualBounceBox.right -= w;
		actualBounceBox.top += h;
		actualBounceBox.bottom -= h;
	}

	@Override
	public void move() {
		super.move();
		centre.x += xspeed;
		centre.y += yspeed;
		if (!actualBounceBox.insideX(centre.x)) xspeed = -xspeed;
		if (!actualBounceBox.insideY(centre.y)) yspeed = -yspeed;
	}
}
