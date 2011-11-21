package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.Countdown;

public class JackInTheBoxAlien extends AlienWithLocation {
	private Countdown openTimer = new Countdown();

	@Override
	public void update() {
		boolean isOpen = openTimer.testAndRun();
		changeAnimation(isOpen ? "open" : "shut");
		Sprite sprite = nextFrame();
		srv.drawSprite(c, sprite);
		if (!isOpen) {
			if (srv.collideAlienWithPlayerHiRes(c, sprite)) {
				srv.getThePlayer().boost(-20);
				srv.playSoundEffect("trampoline");
				openTimer.set(25);
			}
			else {
				freezeBounds = spriteBounds(sprite);
			}
		}
	}
}
