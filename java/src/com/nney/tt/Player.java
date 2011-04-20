package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.LiftAlien;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class Player extends Alien {
	private static final int MONKEY_SNIFF_Y = -34;
	private static final int AIRJUMP_TIME = 3;
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

	private int flashTimer = 50 * 5;

	private boolean drawInWhite;

	private LiftAlien standingOn;

	private int vely;

	public Coord lc;

	private Mode mode = Mode.NORMAL;
	private boolean monkeyLatch;
	private boolean ropeLatch;

	enum Mode {
		NORMAL, MONKEY, ROPE,
	}

	private void invariants() {
		assert !(touchFloor && jumping);
		assert !(touchFloor && inGround);
		assert !(stunTimer != 0 && moveStick);
		assert !(stunTimer != 0 && standingOn != null);

	}

	private void reset() {
		jumping = false;
		vely = 0;
		airJumpTimer = 0;
		mode = Mode.NORMAL;

		standingOn = null;
		touchFloor = false;
	}

	private void fallOff() {
		assert touchFloor;
		airJumpTimer = AIRJUMP_TIME;

		standingOn = null;
		touchFloor = false;

	}

	private void touchDown() {
		assert !touchFloor;
		assert !inGround;
		touchFloor = true;
		jumping = false;
		vely = 0;
	}

	private void jump(int velocity) {
		if (standingOn != null) {
			velocity += standingOn.jumpBoost();
		}
		reset(); // moved here
		vely = velocity;
		jumping = true;
	}

	private void jumpOnFire() {
		if (testStick(Joystick.FIRE)) {
			jump(JUMP_VELOCITY);
		}
	}

	public void stun() {
		// if we not proof and not already stunned ..
		if (proofTimer == 0 && stunTimer == 0) {
			// reset(); from here
			jump(STUN_VELOCITY);
			stunTimer = STUN_TIME;
			moveStick = false;
		}
	}

	public void landOn(LiftAlien lift, int height) {
		reset();
		standingOn = lift;
		c.y = height;
		touchFloor = true;
	}

	private String directionalAnimName(String base) {
		return base + (goLeft ? "left" : "right");
	}

	private int directionalMovement(boolean left, int x) {
		return left ? -x : x;
	}

	private void normalAnimation() {
		boolean animate = true;
		String name;
		if (touchFloor) {
			assert !inGround;
			assert !jumping;
			if (stunTimer != 0) {
				name = "wobble";
				stunTimer--;
				proofTimer = PROOF_TIME;
			}
			else {
				if (moveStick) {
					name = directionalAnimName("");
				}
				else {
					name = directionalAnimName("stood");
				}
			}
		}
		else {
			if (jumping) {
				name = directionalAnimName("jump");
			}
			else {
				name = directionalAnimName("");
				animate = false;
			}
		}
		setAnim(name, animate);
	}

	private void setAnim(String name, boolean animate) {
		changeAnimation(name);
		Sprite s = animate ? nextFrame() : sameFrame();
		srv.registerPlayerSpriteForAlienColisions(c, s);
		playerSprite = s;
	}

	private int getXDelta() {
		moveStick = false;

		int xdelta = 0;
		if (testStick(Joystick.LEFT)) {
			xdelta = -pvt.next();
			goLeft = true;
			moveStick = true;
		}
		else if (testStick(Joystick.RIGHT)) {
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
		srv.validatePlayerPosition(tp);
		xdelta = tp.x - c.x;
		return xdelta;
	}

	private void normalHorizonalSlice(int n) {
		if (inGround) {
			// if you're in the ground it is always possible to move
			c.x += n;
			inGround = srv.inTheGround(c);
		}
		else {
			// if you're in the air we do it
			c.x += n;
			// but if that results in entering the ground ..
			if (srv.inTheGround(c)) {
				// we look at the pixel above
				c.y--;
				if (srv.inTheGround(c)) {
					// it might not get us back into air (in which case we
					// are definitely entering ground from the side)
					c.y++;
					inGround = true;
				}
				else {
					// or it might ... in which case we are touching down
					if (!touchFloor) touchDown();
				}
			}
		}
	}

	private void liftHorizontalSlice(int n) {
		c.x += n;
		if (!standingOn.horizontalOverlap(this)) {
			fallOff();
		}
	}

	private void applyGravity() {
		vely = Math.min(vely + 1, 16);
	}

	private void moveY() {
		// when we are on the floor
		if (touchFloor) {
			assert !inGround;
			assert !jumping;
			if (!srv.playerFall(c, 14)) {
				fallOff();
			}
			else {
				jumpOnFire();
			}
		}

		// when we are in the air
		// (which we might be fresh if we just went offTheEdge() above)
		if (!touchFloor) {
			// jump off the air?
			// we are tolerant and give the player a few frames to jump even
			// after they've run off an edge.
			// This resolves any graphical ambiguity (edges that LOOK rounded)
			// or timing ambiguity (I PRESSED IT)
			// in the player's favour making the whole thing play smoother.
			if (airJumpTimer != 0) {
				jumpOnFire();
			}
			applyGravity();
			MovementSlicer yslicer = new MovementSlicer(vely);
			while (yslicer.more() && !touchFloor) {
				int n = yslicer.next(1);
				if (n < 0) {
					// going up (always possible)
					c.y--;
					inGround = srv.inTheGround(c);
				}
				else {
					// going down
					if (inGround) {
						// if you're in the ground it is always possible
						c.y++;
						inGround = srv.inTheGround(c);
					}
					else {
						// if you're in the air it is possible as long as the
						// pixel below isn't ground
						c.y++;
						if (srv.inTheGround(c)) {
							// and if it is then we touch down
							touchDown();
							c.y--;
						}
					}
				}
			}
		}
	}

	private void move2() {
		// remember our last position
		lc = c.copy();

		if (proofTimer != 0) proofTimer--;
		if (flashTimer != 0) flashTimer--;
		if (airJumpTimer != 0) airJumpTimer--;
		// stunTimer only decrements when touchFloor so isn't done here

		drawInWhite = (flashTimer & 15) > 9;

		if (stunTimer == 0) {
			if (mode == Mode.NORMAL) {
				// start monkey?
				// SCC5
				if (!touchFloor && srv.blockSpecificationIs(c.copyAndMove(0, MONKEY_SNIFF_Y), "hrope")) {
					if (vely >= 0 && !testStick(Joystick.DOWN) && !monkeyLatch) {
						c.y -= 2;
						c.y &= -16;
						c.y += 2;
						mode = Mode.MONKEY;
						System.out.println("Monkey: Start");
					}
				}
				else {
					monkeyLatch = false;
				}
			}
			
			if (mode == Mode.NORMAL) {
				// start vrope
				if (!touchFloor && testRope(0) && testStick(Joystick.DOWN | Joystick.UP)) {
					if (!ropeLatch) {
						goLeft = !goLeft;
						c.x &= -16;
						c.x += 8;
						reset();
						mode = Mode.ROPE;
					}
				}
				else {
					ropeLatch = false;
				}
			}
		}

		if (mode == Mode.MONKEY) {
			boolean success = false; // SCC6
			if (testStick(Joystick.LEFT)) {
				success |= monkeyAttempt(true);
			}
			else if (testStick(Joystick.RIGHT)) {
				success |= monkeyAttempt(false);
			}
			if (!success) {
				setAnim("monkeymid", true);
			}
			if (testStickAA(Joystick.DOWN)) {
				reset();
				monkeyLatch = true;
				c.y -= 6;
				vely = 4;
			}
			if (testStickAA(Joystick.FIRE)) {
				System.out.println("Monkey: Jump off");
				jump(JUMP_VELOCITY);
				monkeyLatch = true;
			}
		}
		
		if (mode == Mode.ROPE){
			// SCC7
			String anim = directionalAnimName("rope");
			boolean moving = false;
			if (testStick(Joystick.UP) && testRope(-2)) {
				c.y += -2;
				moving = true;
			}
			if (testStick(Joystick.DOWN) && testRope(2)) {
				c.y += 2;
				moving = true;
			}
			setAnim(anim, moving);
		}

		if (mode == Mode.NORMAL) {
			if (standingOn != null) {
				standingOn.moveMe(this);
			}
			MovementSlicer xslicer = new MovementSlicer(getXDelta());
			while (xslicer.more()) {
				int n = xslicer.next(1);
				if (standingOn != null) {
					liftHorizontalSlice(n);
				}
				else {
					normalHorizonalSlice(n);
				}
			}
			if (standingOn == null) {
				moveY();
			}
			else {
				jumpOnFire();
			}
			normalAnimation();

		}
	}

	private boolean testRope(int dy) {
		Coord sniffAt = c.copyAndMove(0, dy);
		return srv.blockSpecificationIs(sniffAt, "vrope");
	}

	private boolean monkeyAttempt(boolean left) {
		Coord sniffAt = c.copyAndMove(directionalMovement(left, 8), MONKEY_SNIFF_Y);
		if (!srv.blockSpecificationIs(sniffAt, "hrope")) {
			return false;
		}
		goLeft = left;
		c.x += directionalMovement(left, 3);
		setAnim(directionalAnimName("monkey"), true);
		return true;
	}

	private boolean testStick(int j) {
		return srv.getStick().test(j) && stunTimer == 0;
	}

	private boolean testStickAA(int j) {
		return srv.getStick().testAntiAutofire(j) && stunTimer == 0;
	}

	public void move() {
		invariants();
		move2();
		invariants();
	}

	@Override
	public void init() {
		normalAnimation();
	}

	public void draw() {
		srv.queueSprite(c, playerSprite, drawInWhite);
	}

	public void giveShield() {
		proofTimer = 50 * 13;
		flashTimer = 50 * 12;
	}

	public boolean isStunned() {
		return stunTimer != 0;
	}

	public boolean isReadyToBoardALift() {
		invariants();
		return !isStunned() && standingOn == null && jumping && !inGround;
	}

	@Override
	public void update() {
		// We need this method because the player is a pseudo Alien.
		// Actually, it's move() and draw() that are our entry points.
		// We're the only entity in the game with separate move and draw logic.
		assert false;
	}
}
