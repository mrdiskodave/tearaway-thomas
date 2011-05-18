package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public abstract class LiftAlien extends AlienWithGeneratedLocation {
	private Coord lc;
	private int lastMoveFrmNum;
	private Sprite ourSprite;
	private int width;

	@Override
	public void init() {
		changeAnimation(0);
		ourSprite = nextFrame();
		width = ourSprite.getLiftWidth();
	}

	abstract protected void setPosition();

	/**
	 * This lift moves itself but when the player is on it then the player (who
	 * moves first, in the order of things) needs to move it in order to
	 * establish how to move himself. To simplify this: any method that needs a
	 * lift that has been moved once this frame just calls this method. The risk
	 * of moving this lift twice is then zero.
	 */
	private void moveIfWeNeedTo() {
		int frmNum = srv.getFrameNumber();
		if (frmNum != lastMoveFrmNum) {
			lastMoveFrmNum = frmNum;
			lc = c.copy();
			setPosition();
		}
	}

	private Coord lastFrameDelta() {
		moveIfWeNeedTo();
		Coord delta = c.copy();
		delta.sub(lc);
		return delta;
	}

	@Override
	public void update() {
		moveIfWeNeedTo();

		srv.drawSprite(c, ourSprite);

		Player p = srv.getThePlayer();
		if (p.isReadyToBoardALift()) {
			int landOn = c.y - 1;
			boolean verticalCrossing = p.lc.y < landOn && p.c.y >= landOn;
			if (horizontalOverlap(p) && verticalCrossing) {
				p.startLiftMode(this, landOn);
			}
		}
	}

	public boolean horizontalOverlap(Player p) {
		return p.c.x >= c.x && p.c.x <= (c.x + width);
	}

	public void movePlayer(Player player) {
		player.c.add(lastFrameDelta());
	}

	public int getPlayerJumpBoost() {
		return lastFrameDelta().y;
	}
}
