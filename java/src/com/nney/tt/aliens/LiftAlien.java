package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public abstract class LiftAlien extends Alien {
	private static final int EXTRA_WIDTH = 5;

	private Coord ourPlace = new Coord();
	private Coord lastPlace = new Coord();

	private int lastMoveFrmNum;

	private Sprite ourSprite;
	private int width;

	@Override
	public void onLoaded() {
		ourSprite = firstFrame();
		width = ourSprite.liftWidth() + EXTRA_WIDTH * 2;
		depth = DEPTH_LIFTS_AND_COLLECTABLES;
	}

	abstract protected Coord setPosition();

	/**
	 * This lift moves itself but when the player is on it then the player (who
	 * moves first, in the order of things) needs to move it in order to
	 * establish how to move himself. To simplify this: any method that needs "a
	 * lift that has been moved once this frame" just calls this method. The
	 * risk of moving this lift twice is then zero.
	 */
	private void moveIfWeNeedTo() {
		int frmNum = srv.getFrameNumber();
		if (frmNum != lastMoveFrmNum) {
			lastMoveFrmNum = frmNum;
			lastPlace = ourPlace.copy();
			ourPlace = setPosition();
		}
	}

	private Coord lastFrameDelta() {
		moveIfWeNeedTo();
		Coord delta = ourPlace.copy();
		delta.sub(lastPlace);
		return delta;
	}

	@Override
	public void onPropUpdate() {
		setPosition();
	}

	@Override
	public void update() {
		moveIfWeNeedTo();

		srv.drawSprite(ourPlace, ourSprite);

		Player p = srv.getThePlayer();
		if (p.isReadyToBoardALift()) {
			int landOn = ourPlace.y - 1;
			boolean verticalCrossing = p.lc.y < landOn && p.c.y >= landOn;
			if (horizontalOverlap(p) && verticalCrossing) {
				p.startLiftMode(this, landOn);
			}
		}
	}

	public boolean amIStillOnThisLift(Player player) {
		return horizontalOverlap(player);
	}

	private boolean horizontalOverlap(Player p) {
		int s = ourPlace.x - EXTRA_WIDTH;
		int e = s + width;
		return p.c.x >= s && p.c.x < e;
	}

	public void movePlayer(Player player) {
		player.c.add(lastFrameDelta());
	}

	public int getPlayerJumpBoost() {
		return lastFrameDelta().y;
	}
	
	@Override
	public Coord getLocation() {
		return setPosition();
	}
}
