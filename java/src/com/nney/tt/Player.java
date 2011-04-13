package com.nney.tt;

import org.lwjgl.input.Keyboard;

import com.nney.tt.aliens.Alien;

public class Player extends Alien {

	/**
	 * <code>true</code> to read {@link #VEL_NORM} <code>false</code> to read {@link #VEL_TURBO}.
	 */
	boolean plSprint;
	private static final int[] VEL_NORM = {  1,3,4,5,5,5,5,5 };
	private static final int[] VEL_TURBO = {  1,2,3,4,6,7,9,10 };

	/**
	 * Index into {@link #VEL_NORM} or {@link #VEL_TURBO}.
	 */
	int velStep;

	boolean goLeft;

	@Override
	public void init() {
		stationaryAnim();
	}

	private int getNextVel() {
		int[] t = plSprint ? VEL_TURBO : VEL_NORM;
		int answer = t[velStep];
		if (velStep!=t.length-1) velStep++;
		return answer;
	}

	@Override
	public void move(AlienMovementServices ms) {
		ms.fallOrRaise(c, 5);
		if (ms.testKey(Keyboard.KEY_Q)) {
			changeAnimation("left");
			c.x -= getNextVel();
			ms.validatePlayerPosition(c);
			goLeft = true;
		}
		else if (ms.testKey(Keyboard.KEY_W)) {
			changeAnimation("right");
			c.x += getNextVel();
			ms.validatePlayerPosition(c);
			goLeft = false;
		}
		else if (ms.testKey(Keyboard.KEY_A)) {
//			changeAnimation("left");
			if (ms.getFrameNumber()%25==0) c.x -= 1;
//			ms.validatePlayerPosition(c);
			goLeft = true;
		}
		else if (ms.testKey(Keyboard.KEY_S)) {
//			changeAnimation("right");
			if (ms.getFrameNumber()%25==0) c.x += 1;
//			ms.validatePlayerPosition(c);
			goLeft = false;
		}
		else {
			stationaryAnim();
			velStep = 0;
		}
		ms.scrollTowards(c);
	}

	private void stationaryAnim() {
		changeAnimation(goLeft ? "stoodleft" : "stoodright");
	}

}
