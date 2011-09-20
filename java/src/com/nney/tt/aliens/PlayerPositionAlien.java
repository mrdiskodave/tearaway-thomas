package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class PlayerPositionAlien extends AlienWithLocation {
	@AlienProp(name = "Facing", xtraDef = "leftright", label = "goLeft")
	public boolean goLeft;

	@Override
	public void mapperUpdate() {
		changeAnimation(goLeft ? "stoodleft" : "stoodright");
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = Box.around(c, 40);
	}

	@Override
	public void update() {
		freezeBounds = Box.around(c, 40);
	}
}
