package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class GemAlien extends Alien {
	private static final int FLAG_NO_WOBBLE = 3;
	private static final int FLAG_INVIS = 5;

	private static final int[] WOBBLE = { 0, -1, -2, -3, -2, -1, 0, 1, 2, 3, 2, 1 };

	private boolean wobble;
	private boolean invis;

	
	private int wobblePhase;

	private int scoreTimer;

	private int scoreFrame;
	private boolean falling;

	@Override
	public void load() {
		wobble = !BitOp.test(loadByte(OBflags), FLAG_NO_WOBBLE);
		invis = BitOp.test(loadByte(OBflags), FLAG_INVIS);
	}

	@Override
	public void init() {
		changeAnimation(0);
		wobblePhase = srv.randomness(WOBBLE.length);
	}

	@Override
	public void update() {
	
		if (!invis) {
			normalUpdate();
		}
		else {
			if (falling) {
				if (srv.inTheGround(c.copyAndMove(0, 1))) {
					falling = false;
					invis = false;
					normalUpdate();
				}
				else {
					justDraw();
					c.y++;
				}
			}
			else {
				if (srv.getThePlayer().checkInvisFall(c)) {
					falling = true;
				}
				else {
					if ((srv.getFrameNumber()&31)<16) {
						justDraw();
					}
				}
			}
		}
	}

	private void normalUpdate() {
		if (scoreTimer != 0) {
			changeAnimation(scoreFrame);
			srv.queueSprite(c, nextFrame());
			if (--scoreTimer==0) {
				remove = true;
			}
		}
		else {
			Coord c2 = c.copy();
			if (wobble) {
				c2.y += WOBBLE[wobblePhase++];
				wobblePhase %= WOBBLE.length;
			}
			Sprite s = nextFrame();
			srv.queueSprite(c2, s);
			if (srv.collideAlienWithPlayerHiRes(c2, s)) {
				scoreTimer = 25;
				scoreFrame = 1;
			}

			freezeBounds = Box.around(c, 20, 20);
		}
	}
	
	private void justDraw() {
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
	}
}
