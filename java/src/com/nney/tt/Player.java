package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class Player extends Alien {
	private static final int AIRJUMP_TIME = 4;
	private static final int STUN_TIME = 33;
	private static final int PROOF_TIME = 25;
	private static final int STUN_VELOCITY = -10;
	private static final int JUMP_VELOCITY = -12;
	
	private PlayerVelocityTable pvt = new PlayerVelocityTable();
	
	private Sprite playerSprite;

	boolean goLeft;
	
	private boolean touchFloor = true;
	
	private boolean moveStick;
	
	private boolean inGround;
	
	private boolean jumping;

	private int stunTimer;
	
	private int proofTimer;
	
	private int airJumpTimer;

	private int vely;
	private int flashTimer;

	@Override
	public void init() {
		stationaryAnim();
	}

	public void draw(AlienServices world) {
		world.queueSprite(c, playerSprite);
	}

	private void movePlayer(AlienServices ms) {
		if (proofTimer!=0) proofTimer--;
		
		moveX(ms);
		moveY(ms);
		ms.scrollTowards(c);
		setPlayerAnimation(ms);
	}

	public void move(AlienServices world) {
		invariants();
		movePlayer(world);
		invariants();
	}

	private void invariants() {
		assert !(touchFloor && jumping);
		assert !(touchFloor && inGround);
		assert !(stunTimer!=0 && moveStick);
	}

	private void setPlayerAnimation(AlienServices ms) {
		boolean animate = true;
		if (touchFloor) {
			assert !inGround;
			assert !jumping;
			if (stunTimer != 0) {
				changeAnimation("wobble");
				stunTimer--;
				proofTimer = PROOF_TIME;
			}
			else {
				if (moveStick) {
					changeAnimation(goLeft ? "left" : "right");
				}
				else {
					stationaryAnim();
				}
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

	private void moveX(AlienServices ms) {
		moveStick = false;

		// ----------------------------------------
		// Figure out the xdelta

		int xdelta = 0;
		if (ms.getStick().test(Joystick.LEFT) && stunTimer == 0) {
			xdelta = -pvt.next();
			goLeft = true;
			moveStick = true;
		}
		else if (ms.getStick().test(Joystick.RIGHT) && stunTimer == 0) {
			xdelta = pvt.next();
			goLeft = false;
			moveStick = true;
		}
		else {
			pvt.reset();
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
				// if you're in the ground it is always possible to move
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
						// it might not get us back into air (in which case we
						// are definitely entering ground from the side)
						c.y++;
						inGround = true;
					}
					else {
						// or it might in which case we are touching down
						touchDown();
					}
				}
			}
		}
	}

	private void moveY(AlienServices ms) {
		// ----------------------------------------
		// Y movement
		//

		// when we are on the floor
		if (touchFloor) {
			assert !inGround;
			assert !jumping;
			if (!ms.playerFall(c, 14)) {
				touchFloor = false;
				airJumpTimer = AIRJUMP_TIME;
			}
			else if (ms.getStick().test(Joystick.FIRE) && stunTimer == 0) {
				jump(JUMP_VELOCITY);
			}
		}

		// when we are in the air
		if (!touchFloor) {
			if (airJumpTimer!=0) {
				airJumpTimer--;
				if (ms.getStick().test(Joystick.FIRE) && stunTimer == 0) {
					jump(JUMP_VELOCITY);
				}
			}
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
							touchDown();
							c.y--;
						}
					}
				}
			}
		}
	}

	private void jump(int v) {
		vely = v;
		touchFloor = false;
		jumping = true;
	}

	private void touchDown() {
		assert !inGround;
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
	public void update() {
		assert false;
	}

	public void stun() {
		// if we not proof and not already stunned:
		if (proofTimer==0 && stunTimer == 0) {
			jump(STUN_VELOCITY);
			stunTimer = STUN_TIME;
			moveStick = false;
		}
	}

	public void proof() {
		proofTimer = 50*13;
		flashTimer = 50*12;
		// TODO: AAA flash! but how?? Anim references Sprite
	}

}

