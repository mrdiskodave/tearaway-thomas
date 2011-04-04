package com.nney;

public class Bear extends Alien {
	private int leftLimit;
	private int rightLimit;
	private boolean headedRight;

	public void init() {
		changeAnimation("turn");
	}

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
			c.x++;
			if (c.x > rightLimit) turn = true;
		}
		else {
			changeAnimation("left");
			c.x--;
			if (c.x < leftLimit) turn = true;
		}
		ms.fallOrRaise(c, 16);
		if (ms.getBlockSpecification(c) == "stop") turn = true;
		if (turn) headedRight = !headedRight;
	}
}
