package com.nney.tt.aliens;

public class SpikeAlien extends AlienWithLocation {
	private int freq = 100;
	private int phase = 50;
	private int resume;

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		int frameNumber = srv.getFrameNumber();
		if (frameNumber<resume) {
			freezeBounds = anims.find(0).box().add2(c);
		}
		else {
			animateDrawAndStun(c);
			if (!animPlayer.hasAnimEnded()) {
				animPlayer.rewind();
				
				int a = frameNumber+phase;
				a /= freq;
				a ++;
				a *= freq;
				resume = a;
			}
		}
	}
}
