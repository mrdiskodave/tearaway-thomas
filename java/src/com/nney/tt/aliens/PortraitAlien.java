package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

@AlienInfoAnns({ @AlienInfoAnn(type = 40, gfx = "gpic0"), @AlienInfoAnn(type = 41, gfx = "gpic1"),
		@AlienInfoAnn(type = 43, gfx = "gpic3"), @AlienInfoAnn(type = 35, gfx = "gpic4") })
public class PortraitAlien extends AlienWithLocation {
	@Override
	public void update() {
		Coord ourNose = c.copyAndAdd(17, 17);
		Coord diff = srv.getPlayerPosition().sub2(ourNose);

		diff.y = Math.abs(diff.y) / 2;

		String eyes = "m";
		if (diff.x > diff.y) {
			eyes = "r";
		}
		else if (-diff.x > diff.y) {
			eyes = "l";
		}
		changeAnimation(eyes);

		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
	}
}
