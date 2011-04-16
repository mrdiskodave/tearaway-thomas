package com.nney.tt;

import org.lwjgl.input.Keyboard;

import com.nney.tt.aliens.Alien;
import com.nney.tt.sprites.Sprite;

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
	private boolean gravity = true;
	private Sprite playerSprite;

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

	
	public void move(AlienServices world) {
		movePlayer(world);
		Sprite s = nextFrame();
		world.registerPlayerSpriteForAlienColisions(c, s);
		playerSprite = s;
	}
	
	public void draw(AlienServices world) {
		world.queueSprite(c, playerSprite);
	}

	public void movePlayer(AlienServices ms) {
		if (gravity) {
			ms.fallOrRaise(c, 5);
		}
		if (ms.testKey(Keyboard.KEY_Q)) {
			changeAnimation("left");
			c.x -= getNextVel();
			ms.validatePlayerPosition(c);
			goLeft = true;
			gravity = true;
		}
		else if (ms.testKey(Keyboard.KEY_W)) {
			changeAnimation("right");
			c.x += getNextVel();
			ms.validatePlayerPosition(c);
			goLeft = false;
			gravity = true;
		}
		else if (ms.testKey(Keyboard.KEY_LEFT)) {
			if (ms.getFrameNumber()%15==0) c.x -= 1;
			stationaryAnim();
			gravity = false;
		}
		else if (ms.testKey(Keyboard.KEY_RIGHT)) {
			if (ms.getFrameNumber()%15==0) c.x += 1;
			stationaryAnim();
			gravity = false;
		}
		else if (ms.testKey(Keyboard.KEY_UP)) {
			if (ms.getFrameNumber()%15==0) c.y -= 1;
			gravity = false;
		}
		else if (ms.testKey(Keyboard.KEY_DOWN)) {
			if (ms.getFrameNumber()%15==0) c.y += 1;
			gravity = false;
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
	
	@Override
	public void update(AlienServices world) {
		assert false;
	}

}
