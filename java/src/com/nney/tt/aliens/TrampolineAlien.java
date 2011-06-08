package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class TrampolineAlien extends AlienWithLocation {
	private Box box;

	@Override
	public void visualReset() {
		changeAnimation(0);
		box = anims.find(0).box();
	}

	@Override
	public void update() {
		Box ourBox = box.add2(c);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		int touchDownSpeed = srv.getThePlayer().getTouchDownVel();
		if (touchDownSpeed >= 8) {
			if (srv.collideBoxWithPlayerHandle(ourBox)) {
				// TODO: work takeOffSpeed out from touchDownSpeed?
				// but that could break compatibility on w6.map
				int takeOffSpeed = 20;
				srv.getThePlayer().boost(-takeOffSpeed);
			}
		}
		freezeBounds = ourBox;
	}
}
