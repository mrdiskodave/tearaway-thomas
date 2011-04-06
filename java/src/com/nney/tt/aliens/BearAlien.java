package com.nney.tt.aliens;

import com.nney.tt.AlienMovementServices;

public class BearAlien extends LeftRightAlien {
	@Override
	public void move(AlienMovementServices ms) {
		boolean turned = moveLeftRight(1);
		ms.fallOrRaise(c, 16);
		if (!turned && ms.getBlockSpecification(c) == "stop") {
			headedRight = !headedRight;
		}
		if (ms.collideWithPlayerDP(c, 153,163,165,129)) {
			System.out.println("GOTYA!");
		}
	}
}
