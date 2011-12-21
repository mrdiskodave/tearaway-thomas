package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public abstract class LiftAlien extends Alien {
	private int lastFrameMoved = -100;

	XLift xl;

	@Override
	public void onLoaded() {
		xl = new XLift(firstFrame(), this);
		depth = DEPTH_LIFTS_AND_COLLECTABLES;
	}

	abstract protected Coord currentPosition();

	/**
	 * This lift moves itself but when the player is on it then the player (who
	 * moves first, in the order of things) needs to move it in order to
	 * establish how to move himself. To simplify this: any method that needs "a
	 * lift that has been moved once this frame" just calls this method. The
	 * risk of moving this lift twice is then zero.
	 */
	void generateInternalStateFromFrameNumber() {
		int f = srv.getFrameNumber();
		if (f != lastFrameMoved) {
			lastFrameMoved = f;
		}
		xl.setPos(currentPosition());
	}

	@Override
	public void update() {
		generateInternalStateFromFrameNumber();

		srv.drawSprite(xl.ourPlace, xl.ourSprite);
		srv.getThePlayer().performLiftBoarding(xl, xl.landOn());
	}

	@Override
	public Coord getLocation() {
		generateInternalStateFromFrameNumber();
		return xl.ourPlace;
	}
}
