package com.nney.tt.aliens;

import com.nney.tt.AlienServices;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class ArrowAlien extends Alien {
	private int repeat;
	private int timer;
	private Box box;

	@Override
	public void load() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update(AlienServices world) {
		boolean colide = box.inside(world.getPlayerPosition());
		if (colide) {
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
			if (world.collideAlienWithPlayerBounds(c, s)) {
				world.playerBehind();
			}
			world.queueSprite(c, s);
		}
	}
}
