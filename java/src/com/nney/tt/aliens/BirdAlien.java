package com.nney.tt.aliens;

import com.nney.AlienMovementServices;

public class BirdAlien extends LeftRightAlien {
	@Override
	public void move(AlienMovementServices ms) {
		moveLeftRight(2);
	}
}
