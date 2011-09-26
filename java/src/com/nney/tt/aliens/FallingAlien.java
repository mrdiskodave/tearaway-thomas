package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Anim;


public class FallingAlien extends AlienWithLocation {
	private int vely = -5;
	private int delayedScore;
	private int upBy;
	
	public FallingAlien(Coord start, int delayedScore, int upBy, Anim frightAnim) {
		this.delayedScore = delayedScore;
		this.upBy = upBy;
		c = start.copy();
		animPlayer.changeAnimation(frightAnim);
	}
	
	@Override
	public void update() {
		c.y += vely;
		if (srv.frameTest(2, 1)) {
			vely = Math.min(vely + 1, 8);
			
			if (vely==0 && delayedScore!=0) {
				srv.awardScore(delayedScore, new Coord(c.x, c.y-upBy));
				delayedScore = 0;
			}
		}
		srv.drawSprite(c, nextFrame());
		if (srv.isOffTheBottom(c)) {
			done();
		}
	}
}
