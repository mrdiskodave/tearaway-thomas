package com.nney.tt;

import org.lwjgl.input.Keyboard;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class Player extends Alien {

	/**
	 * <code>true</code> to read {@link #VEL_NORM} <code>false</code> to read
	 * {@link #VEL_TURBO}.
	 */
	boolean plSprint;
	private static final int[] VEL_NORM = { 1, 3, 4, 5, 5, 5, 5, 5 };
	private static final int[] VEL_TURBO = { 1, 2, 3, 4, 6, 7, 9, 10 };

	/**
	 * Index into {@link #VEL_NORM} or {@link #VEL_TURBO}.
	 */
	int velStep;

	private Sprite playerSprite;

	boolean goLeft;
	boolean touchFloor;
	boolean moveStick;

	private int vely;
	private int stunTimer;

	enum MODE {
		STANDING, JUMPING
	};

	@Override
	public void init() {
		stationaryAnim();
	}

	private int getNextVel() {
		int[] t = plSprint ? VEL_TURBO : VEL_NORM;
		if (!touchFloor) {
			velStep = t.length - 1;
		}
		int answer = t[velStep];
		if (velStep != t.length - 1) velStep++;
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
		moveStick = false;
		int xdelta = 0;
		if (ms.testKey(Keyboard.KEY_Q)) {
			xdelta = -getNextVel();
			goLeft = true;
			moveStick = true;
		}
		else if (ms.testKey(Keyboard.KEY_W)) {
			xdelta = getNextVel();
			goLeft = false;
			moveStick = true;
		}
		
		// keep it on screen
		Coord tp = c.copy();
		tp.x += xdelta;
		ms.validatePlayerPosition(tp);
		xdelta = tp.x - c.x;
		
		MovementSlicer slicer = new MovementSlicer(xdelta);
		while (slicer.more()) {
			c.x += slicer.next(1);
			if (!ms.playerFall(c, 14)) {
				vely = 0;
			}
		}
		ms.scrollTowards(c);
		
		if (moveStick) {
			changeAnimation(goLeft ? "left" : "right");
		}
		else {
			stationaryAnim();
		}
		
		
	}

	private void stationaryAnim() {
		changeAnimation(goLeft ? "stoodleft" : "stoodright");
	}

	@Override
	public void update(AlienServices world) {
		assert false;
	}

	public void stun() {
		if (stunTimer != 0) {
			return;
		}
		stunTimer = 33;
		vely = -10;
	}

}

// if (ms.testKey(Keyboard.KEY_LEFT)) {
// if (ms.getFrameNumber()%15==0) c.x -= 1;
// stationaryAnim();
// }
// else if (ms.testKey(Keyboard.KEY_RIGHT)) {
// if (ms.getFrameNumber()%15==0) c.x += 1;
// stationaryAnim();
// }
// else if (ms.testKey(Keyboard.KEY_UP)) {
// if (ms.getFrameNumber()%15==0) c.y -= 1;
// }
// else if (ms.testKey(Keyboard.KEY_DOWN)) {
// if (ms.getFrameNumber()%15==0) c.y += 1;
// }
