package com.nney.tt.aliens;

import com.nney.tt.AlienServices;
import com.nney.tt.sprites.Sprite;

public class BirdAlien extends LeftRightAlien {
	@Override
	public void update(AlienServices ms) {
		moveLeftRight(2);
		Sprite s = nextFrame();
		ms.queueSprite(c, s);
		if (ms.collideAlienWithPlayerHiRes(c, s)) {
			System.out.println("Bird GOTYA!");
		}
	}
}
