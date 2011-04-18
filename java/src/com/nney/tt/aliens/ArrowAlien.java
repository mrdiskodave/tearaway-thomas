package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class ArrowAlien extends Alien {
	private int repeat;
	private int timer;
	private Box box;

	@Override
	public void init() {
		infront = true;
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
			if (timer < 22) {
				on = true;
			}
			if (++timer >= 32) {
				timer = 0;
				repeat--;
			}
		}

		if (on) {
			changeAnimation(0);
			Sprite s = nextFrame();
			srv.queueSprite(c, s);
		}
	}
}
