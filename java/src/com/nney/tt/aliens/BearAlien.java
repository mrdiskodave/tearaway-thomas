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
	}
}
