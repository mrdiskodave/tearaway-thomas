package com.nney.tt.aliens;


public class YellowBirdAlien extends AlienWithLocation {
	private final static BirdTableEntry[] BIRD_TABLE = new BirdTableEntry[] { 
		new BirdTableEntry(0, 100, 75),
		new BirdTableEntry(-300, 20, 100),
		new BirdTableEntry(-200, 20, 150),
		new BirdTableEntry(-100, 30, 200),
		new BirdTableEntry(0, 50, 255),
		new BirdTableEntry(100, 20, 200), new BirdTableEntry(200, 20, 150),
			new BirdTableEntry(300, Integer.MAX_VALUE, 100) };

	private int timer;
	private int speed;
	private int birdTableIdx;

	/**
	 * Bottom 8 bits of a high-resolution y ordinate.
	 */
	private int yrez;

	@Override
	public void onLoaded() {
		changeAnimation(0);
		birdTableIdx = BIRD_TABLE.length - 1;
		loadStep();
	}

	@Override
	public void update() {
		if (timer != 0) {
			timer--;
		}
		else {
			birdTableIdx++;
			if (birdTableIdx >= BIRD_TABLE.length) {
				birdTableIdx = 0;
			}
			loadStep();
		}

		int highRezY = (c.y << 8) + yrez;
		highRezY += speed;
		yrez = highRezY & 0xff;
		int ny = highRezY >> 8;

		int diff = ny - c.y;
		if (diff <= 0) {
			c.y += diff;
		}
		else {
			c.y += diff;
			if (srv.inTheGround(c)) {
				// System.out.println("BONK!");
				while (srv.inTheGround(c)) {
					c.y--;
				}
				birdTableIdx = 0;
				loadStep();
			}
		}

		animateDrawAndStun(c);
	}

	private void loadStep() {
		BirdTableEntry step = BIRD_TABLE[birdTableIdx];
		animPlayer.customiseRate(step.animRate);
		speed = step.speed;
		timer = step.time;
		// System.out.println(String.format("%d: Plan %d frames doing %d (anim %d)",
		// birdTableIdx, timer, speed, step.animRate));
	}
}
