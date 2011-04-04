package com.nney;

public class ArrowAlien extends Alien {
	private int leftLimit;
	private int rightLimit;
	private int topLimit;
	private int bottomLimit;
	
	private int repeat;
	private int timer;

	@Override
	public void load() {
		leftLimit = loadShort(OBleft);
		rightLimit = loadShort(OBright);
		topLimit = loadShort(OBtop);
		bottomLimit = loadShort(OBbottom);
	}

	@Override
	public void move(AlienMovementServices world) {
		boolean on = false;

		Coord c = world.getPlayerPosition();
		boolean colide = c.x >= leftLimit && c.x <= rightLimit && c.y >= topLimit
				&& c.y <= bottomLimit;
		if (colide) {
			repeat = 8;
		}

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
