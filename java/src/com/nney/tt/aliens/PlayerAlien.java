package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Anim;

/**
 * The starting position of the {@link Player} in the level is marked by a
 * {@link PlayerAlien}. Being an {@link Alien}, it can participate in loading
 * and saving and level editing and stuff. The {@link Player} is created from
 * the information that this object contains.
 */
public class PlayerAlien extends AlienWithLocation {
	@AlienProp(name = "Facing", xtraDef = "leftright", label = "goLeft")
	public boolean goLeft;

	@Override
	public Anim mapperAnim() {
		return anims.find(goLeft ? "stoodleft" : "stoodright");
	}

	@Override
	public void update() {
		freezeBounds = Box.around(c, 40);
	}
}
