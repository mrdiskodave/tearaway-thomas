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
	boolean touchFloor = true;
	boolean moveStick;

	private int vely;
	private int stunTimer;
	private boolean inGround;
	private boolean jumping;

	enum MODE {
		STANDING, JUMPING
	};

	@Override
	public void init() {
		stationaryAnim();
	}

	private int getNextVelStep() {
		int[] t = plSprint ? VEL_TURBO : VEL_NORM;
		int answer = t[velStep];
		if (velStep != t.length - 1) velStep++;
		return answer;
	}

	public void move(AlienServices world) {
		movePlayer(world);
	}

	public void draw(AlienServices world) {
		world.queueSprite(c, playerSprite);
	}

	public void movePlayer(AlienServices ms) {
		moveStick = false;
		
		// ----------------------------------------
		// Figure out the xdelta
		
		int xdelta = 0;
		if (ms.testKey(Keyboard.KEY_Q)) {
			xdelta = -getNextVelStep();
			goLeft = true;
			moveStick = true;
		}
		else if (ms.testKey(Keyboard.KEY_W)) {
			xdelta = getNextVelStep();
			goLeft = false;
			moveStick = true;
		}
		else {
			velStep = 0;
		}

		// keep it on screen
		Coord tp = c.copy();
		tp.x += xdelta;
		ms.validatePlayerPosition(tp);
		xdelta = tp.x - c.x;

		// ----------------------------------------
		// X movement

		MovementSlicer xslicer = new MovementSlicer(xdelta);
		while (xslicer.more()) {
			int n = xslicer.next(1);
			if (inGround) {
				// if you're in the ground it is always possible
				c.x += n;
				inGround = ms.inTheGround(c);
			}
			else {
				// if you're in the air we do it
				c.x += n;
				// but if that results in entering the ground ..
				if (ms.inTheGround(c)) {
					// we look at the pixel above
					c.y--;
					if (ms.inTheGround(c)) {
						// it might not save us (in which case we are definately
						// entering ground)
						c.y++;
						inGround = true;
					}
					else {
						// or it might!
						jumpingOff();
					}
				}
			}
		}

		// ----------------------------------------
		// Y movement
		//

		// when we're on the floor
		if (touchFloor) {
			assert !inGround;
			if (!ms.playerFall(c, 14)) {
				touchFloor = false;
			}
			else if (ms.testKey(Keyboard.KEY_SPACE)) {
				vely = -12;
				touchFloor = false;
				jumping = true;
			}
		}

		if (!touchFloor) {
			gravity();
			MovementSlicer yslicer = new MovementSlicer(vely);
			while (yslicer.more() && !touchFloor) {
				int n = yslicer.next(1);
				if (n < 0) {
					// going up (always possible)
					c.y--;
					inGround = ms.inTheGround(c);
				}
				else {
					// going down
					if (inGround) {
						// if you're in the ground it is always possible
						c.y++;
						inGround = ms.inTheGround(c);
					}
					else {
						// if you're in the air it is possible as long as the
						// pixel below isn't ground
						c.y++;
						if (ms.inTheGround(c)) {
							jumpingOff();
							c.y--;
						}
					}
				}
			}
		}

		ms.scrollTowards(c);

		boolean animate = true;
		if (touchFloor) {
			if (moveStick) {
				changeAnimation(goLeft ? "left" : "right");
			}
			else {
				stationaryAnim();
			}
		}
		else {
			if (jumping) {
				changeAnimation(goLeft ? "jumpleft" : "jumpright");
			}
			else {
				animate = false;
			}
		}

		Sprite s = animate ? nextFrame() : currentFrame();
		ms.registerPlayerSpriteForAlienColisions(c, s);
		playerSprite = s;
	}

	private void jumpingOff() {
		touchFloor = true;
		jumping = false;
		vely = 0;
	}

	private void gravity() {
		vely++;
		vely = Math.min(vely, 16);
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
