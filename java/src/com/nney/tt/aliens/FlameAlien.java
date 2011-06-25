package com.nney.tt.aliens;

import com.nney.tt.geom.Box;


@AlienInfoAnns({
	@AlienInfoAnn(type = 46, gfx = "glflm", score=2500),
	@AlienInfoAnn(type = 47, gfx = "grflm", score=500)
})
public class FlameAlien extends AlienWithLocation {
	private int pause;

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		if (pause>0) {
			pause--;
			freezeBounds = Box.around(c, 100, 50);
		}
		else {
			animateDrawAndStun(c);
			if (animPlayer.hasAnimEnded()) {
				animPlayer.rewind();
				pause = srv.randomness(64)+25;
			}
		}
	}
}
