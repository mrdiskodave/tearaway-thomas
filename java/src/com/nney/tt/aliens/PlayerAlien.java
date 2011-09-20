package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

/**
 * The starting position of the {@link Player} in the map is marked by a
 * {@link PlayerAlien}. Being an {@link Alien}, it can participate in loading
 * and saving and map editing and stuff. The {@link Player} is created from the
 * information this object contains.
 */
public class PlayerAlien extends AlienWithLocation {
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
