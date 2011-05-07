package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class ScoreNoticeAlien extends Alien {
	private int what;
	private int timer;
	private int vely;

	public ScoreNoticeAlien(int what, Coord where) {
		this.what = what;
		c = where;
		timer = 40;
	}
	
	@Override
	public void init() {
		changeAnimation(Integer.toString(what));
		depth = DEPTH_FOREGROUND;
	}

	@Override
	public void update() {
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (--timer<0) {
			done();
		}
		c.y -= vely+1;
//		if (srv.frameTest(4, 1)) {
//			vely ++;
//		}
	}

}
