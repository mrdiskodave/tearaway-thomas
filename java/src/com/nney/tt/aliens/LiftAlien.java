package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public abstract class LiftAlien extends Alien {
	// if this is null it suggests the subclass forgot to dimension()
	// itself during onPropUpdate()
	LiftImpl[] lifts;

	@Override
	public void onLoaded() {
		depth = DEPTH_LIFTS;
		// default dimension
		dimension(1);
	}

	void dimension(int d) {
		lifts = new LiftImpl[d];
		for (int n = 0; n < lifts.length; n++) {
			lifts[n] = new LiftImpl(firstFrame());
		}
	}

	abstract protected Coord[] currentPosition();

	Coord[] validatedCurrentPosition() {
		Coord[] answer = currentPosition();
		assert answer.length == lifts.length;
		return answer;
	}

	public void move() {
		Coord[] pos = validatedCurrentPosition();
		for (int n = 0; n < lifts.length; n++) {
			lifts[n].setPos(pos[n]);
		}
	}

	@Override
	public void update() {
		// only draw
		for (LiftImpl lift : lifts) {
			srv.drawSprite(lift.ourPlace, lift.ourSprite);
			srv.getThePlayer().performLiftBoarding(lift, lift.landOn());
		}
	}

	@Override
	public void mapperUpdate() {
		Coord[] pos = validatedCurrentPosition();
		for (int n = 0; n < lifts.length; n++) {
			srv.drawSprite(pos[n], firstFrame());
		}
	}

	@Override
	public Coord getLocation() {
		Coord[] pos = validatedCurrentPosition();
		return pos[0];
	}
}
