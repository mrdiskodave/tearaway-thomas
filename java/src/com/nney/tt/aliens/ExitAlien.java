package com.nney.tt.aliens;

import com.nney.tt.sprites.Sprite;

public class ExitAlien extends AlienWithLocation {
	@Override
	public void onLoaded() {
		depth = DEPTH_FOREGROUND;
	}
	
	@Override
	public void update() {
		changeAnimation(srv.isExitOpen() ? "open" : "shut");
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
	}
}
