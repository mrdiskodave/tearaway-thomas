package com.nney;

public class BirdAlien extends Alien {
	private int leftLimit;
	private int rightLimit;
	private boolean headedRight;

	@Override
	public void load() {
		leftLimit = loadShort(OBleft);
		rightLimit = loadShort(OBright);
		headedRight = BitOp.test(loadByte(OBflags), 0);
	}

	@Override
	public void move(AlienMovementServices ms) {
		boolean turn = false;
		if (headedRight) {
			changeAnimation("right");
			c.x += 2;
			if (c.x > rightLimit) turn = true;
		}
		else {
			changeAnimation("left");
			c.x -= 2;
			if (c.x < leftLimit) turn = true;
		}
		if (turn) headedRight = !headedRight;
	}
}
