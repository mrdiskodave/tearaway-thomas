package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class MagicDustAlien extends AlienWithLocation {
	public MagicDustAlien(Coord where) {
		c = where;
	}

	@Override
	public void visualReset() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (animPlayer.hasAnimEnded()) {
			done();
		}
	}
}
