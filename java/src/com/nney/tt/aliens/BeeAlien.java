package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class BeeAlien extends AlienWithLocation {
	@AlienProp(name = "AdviceBox", doc = "The area we're confined to")
	private Box box;
	
	private Coord d;

	@Override
	public void loadFromLegacyData() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}
	
	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(c, 50);
		box.add(new Coord(25, 0));
	}

	
	@Override
	public void visualReset() {
		changeAnimation(0);
		d = c.copy();
	}
	
	@Override
	public void update() {
		Coord lc = c.copy();
		c.closer(d, 2);
		if (c.equals(d)) {
			nextDestination();
		}
		int dx = c.x - lc.x;
		if (dx>0) {
			changeAnimation("right");
		}
		if (dx<0) {
			changeAnimation("left");
		}

		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
		
		freezeBounds = box.copy();
		freezeBounds.shrink(-50); // TODO: measure all sprites?
		
	}
	
	private void nextDestination() {
		Coord p = srv.getPlayerPosition();
		d.closer(p, 40);
		box.constrain(d);
		d.x += srv.randomness(81)-40;
		d.y += srv.randomness(81)-40;
	}
}
