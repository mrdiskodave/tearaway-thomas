package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class LiftAlien extends Alien {
	private Box box;
	private Coord lc;
	private int lastMove;

	@Override
	public void load() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	static int sine(int idx) {
		int maxInput = 1024;
		int maxOutput = 1024;
		idx &= maxInput - 1;
		double angle = (2 * Math.PI * idx) / maxInput;
		return (int) (Math.sin(angle) * maxOutput);
	}

	@Override
	public void update() {
		moveIfWeNeedTo();

		changeAnimation(0);
		Sprite s = nextFrame();
		srv.queueSprite(c, s);

		Player p = srv.getThePlayer();
		if (p.isHappyToBoardALift()) {
			int landOn = c.y - 1;
			boolean verticalCrossing = p.lc.y < landOn && p.c.y >= landOn;
			if (horizontalOverlap(p) && verticalCrossing) {
				p.landOn(this, landOn);
			}
		}
	}

	public boolean horizontalOverlap(Player p) {
		return p.c.x >= c.x && p.c.x <= (c.x + 44);
	}

	private void moveIfWeNeedTo() {
		int f = srv.getFrameNumber();
		if (f != lastMove) {
			lastMove = f;
			lc = c.copy();
			setPosition();
		}
	}

	private void setPosition() {
		int angle = srv.getFrameNumber() * 4;
		Coord origin = new Coord((box.left + box.right) / 2, box.top);
		int spin = sine(angle) / 4 + 256;
		int xo = sine(spin + 256) * box.width();
		int yo = sine(spin) * box.height();
		xo /= 1024 * 2;
		yo /= 1024;
		c.x = origin.x + xo;
		c.y = origin.y + yo;
	}

	public void moveMe(Player player) {
		moveIfWeNeedTo();

		Coord z = c.copy();
		z.sub(lc);
		player.c.add(z);
	}
}
