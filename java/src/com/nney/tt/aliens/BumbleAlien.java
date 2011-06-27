package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public abstract class BumbleAlien extends AlienWithLocation {
	@AlienProp(name = "Area", doc = "The area we're confined to", label = "box")
	public Box box;
	
	protected Coord d;

	@Override
	public void loadFromLegacyData() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}
	
	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(c, 100);
		c.y += 50;
	}

	
	@Override
	public void onLoaded() {
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
		bumbleAnimation(lc);

		animateDrawAndStun(c);
		
		freezeBounds = box.copy();
		int grow = 50+travelBeyondBox(); // TODO: measure all sprites?
		freezeBounds.shrink(-grow); 
		
	}

	public int travelBeyondBox() {
		return 0;
	}

	public  void bumbleAnimation(Coord lc) {
	}
	
	abstract public void nextDestination();
}
