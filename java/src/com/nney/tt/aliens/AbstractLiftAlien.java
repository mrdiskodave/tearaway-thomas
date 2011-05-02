package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public abstract class AbstractLiftAlien extends Alien {
	private Coord lc;
	private int lastMove;
	
	@Override
	public void init() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		moveIfWeNeedTo();

		Sprite s = nextFrame();
		srv.queueSprite(c, s);

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
		return p.c.x >= c.x && p.c.x <= (c.x + 44);
		// TODO: hardwired constant!
	}

	private void moveIfWeNeedTo() {
		int f = srv.getFrameNumber();
		if (f != lastMove) {
			lastMove = f;
			lc = c.copy();
			setPosition();
		}
	}
	

	public void moveMe(Player player) {
		player.c.add(lastFrameDelta());
	}
	
	public int jumpBoost() {
		return lastFrameDelta().y;
	}

	private Coord lastFrameDelta() {
		moveIfWeNeedTo();
		Coord delta = c.copy();
		delta.sub(lc);
		return delta;
	}

	abstract protected void setPosition();
}
