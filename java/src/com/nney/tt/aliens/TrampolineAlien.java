package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class TrampolineAlien extends AlienWithLocation {
	private Box box;

	@Override
	public void onLoaded() {
		changeAnimation(0);
		box = anims.find(0).getBounds();
	}

	@Override
	public void update() {
		Box ourBox = box.add2(c);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		int touchDownSpeed = srv.getThePlayer().getTouchDownVel();
		if (touchDownSpeed >= 8) {
			if (srv.collideBoxWithPlayerHandle(ourBox)) {
				srv.getThePlayer().boost(-20);
				srv.playSoundEffect("trampoline");
			}
		}
		freezeBounds = ourBox;
	}
}
