package com.nney.tt.aliens;

import com.nney.tt.AlienMovementServices;
import com.nney.tt.geom.Box;

public class BearAlien extends LeftRightAlien {
	private static final Box COLLISION_BOX = new Box(153,163,165,129);

	@Override
	public void move(AlienMovementServices ms) {
		boolean turned = moveLeftRight(1);
		ms.fallOrRaise(c, 16);
		if (!turned && ms.getBlockSpecification(c) == "stop") {
			headedRight = !headedRight;
		}
		if (ms.collideWithPlayerDP(c, COLLISION_BOX)) {
			System.out.println("GOTYA!");
		}
	}
}
