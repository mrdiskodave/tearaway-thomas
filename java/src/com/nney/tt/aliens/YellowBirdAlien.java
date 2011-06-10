package com.nney.tt.aliens;

import com.nney.tt.sprites.AnimPlayer;

public class YellowBirdAlien extends AlienWithLocation {
	class Step {
		final int speed;
		final int time;
		final int animRate;

		public Step(int speed, int time, int animRate) {
			this.speed = speed;
			this.time = time;
			this.animRate = animRate;
		}
	};
	
	int step;
	int timer;

	Step[] steps = new Step[] { new Step(0, 50, 75), new Step(-300, 20, 100), new Step(-200, 20, 150),
			new Step(-100, 30, 200), new Step(0, 50, 255), new Step(100, 20, 200), new Step(200, 20, 150),
			new Step(300, Integer.MAX_VALUE, 100) };

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		// TODO: are step and our timer aren't really the kinds of things that need saving -- are they??
		// maybe they are just not the kinds of things that need editting!
		// TODO: 00: ybird!!!
	}
}
