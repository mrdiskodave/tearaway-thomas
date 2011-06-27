package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class ScoreNoticeAlien extends AlienWithLocation {
	private int amount;
	private int timer;
	private int vely;

	public ScoreNoticeAlien(int amount, Coord where) {
		assert amount>=0;
		this.amount = amount;
		c = where;
		timer = 40;
	}

	@Override
	public void onLoaded() {
		changeAnimation(Integer.toString(amount));
		depth = DEPTH_FOREGROUND;
	}

	@Override
	public void update() {
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (--timer < 0) {
			done();
		}
		c.y -= vely + 1;
		// if (srv.frameTest(4, 1)) {
		// vely ++;
		// }
	}

}
