package com.nney;

import org.lwjgl.input.Keyboard;

public class Player extends Alien {

	private static final int[] vel_norm = {  1,3,4,5,5,5,5,5 };
	private static final int[] vel_turbo = {  1,2,3,4,6,7,9,10 };
	int velStep;
	boolean goLeft;
	boolean plSprint;

	public void init() {
		stationaryAnim();
	}

	private int getNextVel() {
		int[] t = plSprint ? vel_turbo : vel_norm;
		int answer = t[velStep];
		if (velStep!=t.length-1) velStep++;
		return answer;
	}

	public void move(AlienMovementServices ms) {
		ms.fallOrRaise(c, 5);
		if (ms.testKey(Keyboard.KEY_Q)) {
			changeAnimation("runleft");
			c.x -= getNextVel();
			validatePlX();
			goLeft = true;
		}
		else if (ms.testKey(Keyboard.KEY_W)) {
			changeAnimation("runright");
			c.x += getNextVel();
			validatePlX();
			goLeft = false;
		}
		else {
			stationaryAnim();
			velStep = 0;
		}
	}

	private void validatePlX() {
		// don't do this in relation to the screen like we used to!
		// very problematic if the screen is scrolling to find the player!
		// (e.g. teleports!)

		c.x = Math.max(c.x, 6);
	}

	private void stationaryAnim() {
		changeAnimation(goLeft ? "stoodleft" : "stoodright");
	}

}
