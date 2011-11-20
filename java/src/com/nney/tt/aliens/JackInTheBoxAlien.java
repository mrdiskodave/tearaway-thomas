package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.Countdown;

public class JackInTheBoxAlien extends AlienWithLocation {
	private Countdown open = new Countdown();

	@Override
	public void update() {
		boolean isOpen = open.testAndRun();
		changeAnimation(isOpen ? "open" : "shut");
		Sprite sprite = nextFrame();
		srv.drawSprite(c, sprite);
		if (!isOpen && srv.collideAlienWithPlayerHiRes(c, sprite)) {
			srv.getThePlayer().boost(-20);
			srv.playSoundEffect("trampoline");
			open.set(25);
		}
	}
}
