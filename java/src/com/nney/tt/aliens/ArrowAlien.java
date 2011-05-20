package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class ArrowAlien extends Alien {
	private int repeat;

	@AlienProp(name = "AdviceBox", doc = "Player's location for us to blink at him?")
	public Box box;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(c, 32);
	}

	@Override
	public void visualReset() {
		depth = DEPTH_FOREGROUND;
	}

	@Override
	public void loadFromLegacyData() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		boolean collide = box.inside(srv.getPlayerPosition());
		if (collide) {
			repeat = 8;
		}

		boolean on = false;
		if (repeat != 0) {
			int frm = srv.getFrameNumber() & 31;
			if (frm < 22) {
				on = true;
			}
			else if (frm == 31) {
				repeat--;
			}
		}

		if (on) {
			changeAnimation(0);
			Sprite s = nextFrame();
			srv.drawSprite(c, s);
		}
	}
}
