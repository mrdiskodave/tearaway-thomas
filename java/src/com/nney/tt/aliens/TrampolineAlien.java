package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class TrampolineAlien extends AlienWithLocation {
	@Override
	public void visualReset() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		int touchDownSpeed = srv.getThePlayer().getTouchDownVel();
		if (touchDownSpeed>=8) {
			Coord pp = srv.getPlayerPosition();
			int diff = pp.x - c.x;
			int w = animPlayer.current().w;
			if (diff>=0 && diff<w) {
				// work this out from touchDownSpeed?
				// but that could break compatibility on w6.map
				int takeOffSpeed = 20;
				srv.getThePlayer().boost(-takeOffSpeed);
			}
		}
		freezeBounds = boxAroundUs(50); // TODO: measure all sprites?
	}
}
