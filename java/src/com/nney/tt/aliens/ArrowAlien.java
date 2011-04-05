package com.nney.tt.aliens;

import com.nney.AlienDrawingServices;
import com.nney.AlienMovementServices;
import com.nney.tt.geom.Box;

public class ArrowAlien extends Alien {
	
	private int repeat;
	private int timer;
	private Box box;

	@Override
	public void load() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void move(AlienMovementServices world) {
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
		}
		else {
			hide();
		}
	}

	@Override
	public void draw(AlienDrawingServices world) {
		super.draw(world);
		// world.debugText(c, String.format("%d/%d", repeat, timer));
	}
}
