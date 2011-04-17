package com.nney.tt.aliens;

import com.nney.tt.AlienServices;
import com.nney.tt.sprites.Sprite;

public class BearAlien extends LeftRightAlien {
	@Override
	public void update(AlienServices ms) {
		boolean turned = moveLeftRight(1);
		if (!ms.playerFall(c, 16)) {
			remove = true;
		}
		if (!turned && ms.getBlockSpecification(c) == "stop") {
			headedRight = !headedRight;
		}
		Sprite s = nextFrame();
		ms.queueSprite(c, s);
		if (ms.collideAlienWithPlayerHiRes(c, s)) {
			ms.stunThePlayer();
		}
	}
}
