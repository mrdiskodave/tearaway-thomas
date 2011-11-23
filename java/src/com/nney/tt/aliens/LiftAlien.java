package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.Latch;

public abstract class LiftAlien extends Alien {
	private static final int EXTRA_WIDTH = 4;
	private int lastFrameMoved = -100;

	private Coord ourPlace = new Coord();
	private Coord lastPlace = new Coord();

	private Sprite ourSprite;

	public int left;
	public int width;

	@Override
	public void onLoaded() {
		ourSprite = firstFrame();
		width = ourSprite.liftWidth() + EXTRA_WIDTH * 2;
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
	private void generateInternalStateFromFrameNumber() {
		int f = srv.getFrameNumber();
		if (f != lastFrameMoved) {
			lastFrameMoved = f;
			lastPlace = ourPlace.copy();
			ourPlace = currentPosition();
			left = ourPlace.x - EXTRA_WIDTH;
		}
	}

	public Coord lastFrameDelta() {
		generateInternalStateFromFrameNumber();
		Coord delta = ourPlace.copy();
		delta.sub(lastPlace);
		return delta;
	}

	@Override
	public void update() {
		generateInternalStateFromFrameNumber();

		srv.drawSprite(ourPlace, ourSprite);

		int landOn = ourPlace.y - 1;
		srv.getThePlayer().performLiftBoarding(this, landOn);
	}

	@Override
	public Coord getLocation() {
		generateInternalStateFromFrameNumber();
		return ourPlace;
	}
}
