package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class ArrowAlien extends Alien {
	private int repeat;
	
	@AlienProp(name="AdviceBox", doc="Player's location for us to blink at him?")
	public Box box;

	@Override
	public void init() {
		depth = DEPTH_FOREGROUND;
	}
	
	@Override
	public void load() {
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
			int frm = srv.getFrameNumber()&31;
			if (frm < 22) {
				on = true;
			}
			else if (frm==31) {
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
