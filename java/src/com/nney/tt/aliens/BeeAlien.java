package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public class BeeAlien extends BumbleAlien {
	private static final int BUMBLE = 40;

	@Override
	public int travelBeyondBox() {
		return BUMBLE;
	}

	@Override
	public  void bumbleAnimation(Coord lc) {
		int dx = c.x - lc.x;
		if (dx>0) {
			changeAnimation("right");
		}
		if (dx<0) {
			changeAnimation("left");
		}
	}
	
	@Override
	public void nextDestination() {
		Coord p = srv.getPlayerPosition();
		d.closer(p, 40);
		box.constrain(d);
		d.x += srv.randomness(BUMBLE*2+1)-BUMBLE;
		d.y += srv.randomness(BUMBLE*2+1)-BUMBLE;
	}
}
