package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class ExitAlien extends AlienWithLocation {
	@Override
	public void onLoaded() {
		depth = DEPTH_FG_SCENARY;
	}

	@Override
	public void update() {
		boolean isOpen = srv.isExitOpen();
		changeAnimation(isOpen ? "open" : "shut");
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (isOpen && srv.collideBoxWithPlayer(Box.around(c, 2))) {
			srv.levelCompleted(c);
		}
	}
}
