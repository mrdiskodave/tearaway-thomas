package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.LiftAlien;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class Player extends Alien {
	// ---------------------------------------------------------------------------
	// CONSTANTS

	/**
	 * How much do we tolerate the player being misplaced for getting on a
	 * ladder when they are standing still? They get the ideal position plus
	 * {@link #LADDER_XSNAP_STATIONARY} pixels on either side.
	 */
	private static final int LADDER_XSNAP_STATIONARY = 5;

	private static final int VROPE_SNIFF_Y = -17;
	private static final int VROPE_SNIFF_YPLUS = 11;
	private static final int HROPE_SNIFF_Y = -34;

	private static final int AIRJUMP_TIME = 4;
	private static final int STUN_TIME = 33;
	private static final int PROOF_TIME = 25;
	private static final int STUN_VELOCITY = -10;
	private static final int JUMP_VELOCITY = -12;

	/**
	 * How big a pixel step is counted as part of the continuous surface of the
	 * floor? Bigger steps are ground that the player jumps into from the side
	 * (rather walking on top of i.e. mounting). The bigger this value the more
	 * the player will visibly "mount" sign posts and tree branches and other
	 * platforms during his jumps (which looks bad). The smaller this value the
	 * greater the chance of falling through the floor if the map designer
	 * hasn't taken care to observe the original "
	 * {@link #FLOOR_DEFINITION_DISTANCE} = 1" rule.
	 */
	private static final int FLOOR_DEFINITION_DISTANCE = 3;
	// 3 for now.
	// e.g. TTResource.map("w", 5) contains an example of such a spot.
	// There is a 3 pixel step because of single misplaced block.
	//

	/**
	 * With this switched on <b>any</b> size pixel step is counted as part of
	 * the continuous surface of the floor once {@link #touchFloor} is
	 * <code>true</code>.
	 * 
	 * Then if you "want" to get through a >{@link #FLOOR_DEFINITION_DISTANCE}
	 * pixel size step at floor level you'll need to jump through it. Jumping
	 * through something so small at floor level will be hard because you have
	 * to jump <i>from</i> the floor and your jump return-velocity will be too
	 * big to allow such sneaky manoeuvres. Probably. With this compile time
	 * configuration set off (i.e. to <code>false</code>) you can just walk
	 * through the gap easily and probably fall forever after that. i.e. this
	 * configuration hides map problems which is probably only a good thing in
	 * the final version where they cannot be fixed.
	 */
	private static final boolean CTC_MITIGATE_AGAINST_FALLTHROUGH = true;

	// I think the original had FLOOR_DEFINITION_DISTANCE = 1
	// and CTC_MITIGATE_AGAINST_FALLTHROUGH = true

	// TODO: hollow out the masks for sign posts and trees.
	// We just want a single pixel running along the top of
	// each place where the player can stand.
	// Then the only issue is other platforms which doesn't happen much
	// so we can crank FLOOR_DEFINITION_DISTANCE up a bit?

	// TODO: reset the level if the player does manage to fall through
	// (not something we ever did in the original)

	// ---------------------------------------------------------------------------
	// FIELDS

	/**
	 * Player accelerates from standing and this object manages that.
	 */
	private PlayerVelocityTable pvt = new PlayerVelocityTable();

	/**
	 * What does the player look like?
	 */
	private Sprite playerSprite;

	/**
	 * Is the {@link #playerSprite} to be drawn as a white silhouette? We do
	 * this to show they are invulnerable.
	 */
	private boolean drawInWhite;

	/**
	 * Is the player facing left? <code>true</code> means "they are facing left"
	 * and <code>false</code> means "they are facing right".
	 */
	boolean goLeft;

	/**
	 * Is the player on the floor?
	 */
	private boolean touchFloor = true;

	/**
	 * Is the player moving the stick to the left or the right in
	 * {@link Mode#NORMAL}?
	 */
	private boolean moveStick;

	/**
	 * Is the player in the ground?
	 */
	private boolean inGround;

	/**
	 * Is the player jumping?
	 */
	private boolean jumping;

	/**
	 * The player is stunned until this timer counts down to zero.
	 */
	private int stunTimer;

	/**
	 * The player is invulnerable until this timer counts down to zero.
	 */
	private int proofTimer;

	/**
	 * The player is able to jump off the air until this timer counts down to
	 * zero.
	 * 
	 * You see, we are tolerant and give the player a few frames to jump even
	 * after they've run off an edge. This resolves any graphical ambiguity
	 * (edges that <b>look</b> rounded) or timing ambiguity (<b>I pressed
	 * it!</b>) in the player's favour - making the whole thing play smoother.
	 */
	private int airJumpTimer;

	private int flashTimer;

	/**
	 * A lift, if we are standing on one, otherwise <code>null</code>.
	 */
	private LiftAlien standingOn;

	/**
	 * Our Y velocity.
	 */
	private int vely;

	/**
	 * Our last coordinate.
	 */
	public Coord lc;

	/**
	 * What {@link Mode} are we in?
	 */
	private Mode mode = Mode.NORMAL;

	/**
	 * A flag that tells us not to go right back into {@link Mode#MONKEY}
	 * directly after leaving it.
	 */
	private boolean monkeyLatch;

	/**
	 * A flag that tells us not to go right back into {@link Mode#ROPE} directly
	 * after leaving it.
	 */
	private boolean ropeLatch;
	private boolean ladderLatch;

	// ---------------------------------------------------------------------------
	// ENUMERATIONS

	enum Mode {
		NORMAL, MONKEY, ROPE, ROPE_TWIST, LADDER
	}

	enum LR {
		NO, LEFT, RIGHT
	}

	// ---------------------------------------------------------------------------
	// PRIVATE SUBROUTINES

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

	private void jumpV(int velocity) {
		if (standingOn != null) {
			velocity += standingOn.jumpBoost();
		}
		reset(); // moved here
		vely = velocity;
		jumping = true;
	}

	private void jumpOnFire() {
		if (testStick(Joystick.FIRE)) {
			jump();
		}
	}

	private String directionalAnimName(String base) {
		return base + (goLeft ? "left" : "right");
	}

	private int directionalMovement(boolean left, int x) {
		return left ? -x : x;
	}

	private void setAnim(String name, boolean animate) {
		changeAnimation(name);
		Sprite s = animate ? nextFrame() : sameFrame();
		srv.registerPlayerSpriteForAlienColisions(c, s);
		playerSprite = s;
	}

	private int getStickUpDownDelta() {
		int delta = 0;
		if (testStick(Joystick.UP)) {
			delta--;
		}
		if (testStick(Joystick.DOWN)) {
			delta++;
		}
		return delta;
	}

	private boolean testStick(int j) {
		return srv.getStick().test(j) && stunTimer == 0;
	}

	private boolean testStickAA(int j) {
		return srv.getStick().testAntiAutofire(j) && stunTimer == 0;
	}

	// ---------------------------------------------------------------------------
	// NORMAL MODE

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
		return keepXDeltaOnScreen(xdelta);
	}

	private int keepXDeltaOnScreen(int xdelta) {
		Coord tp = c.copy();
		tp.x += xdelta;
		srv.validatePlayerPosition(tp);
		xdelta = tp.x - c.x;
		return xdelta;
	}

	private void normalHorizonalSlice(int n) {
		// The floor is two pixels: one air (with air above), and below it, one
		// ground (with ground below).
		// When the player's position is that of that one air pixel they
		// touchFloor.
		// Next to it there can be more floor: either on the same level
		// or 1 pixel up or 1 pixel down.
		//
		// If there are any >1 pixel steps in the floor
		// that you could fall through!
		// TTResource.map("w", 5) contains an example of such a spot.
		// There is a 3 pixel step because of single misplaced block.
		//
		c.x += n;
		if (touchFloor && CTC_MITIGATE_AGAINST_FALLTHROUGH) {
			vacuumFloor();
		}
		else {
			if (inGround) {
				// if you're in the ground it is always possible to move
				inGround = srv.inTheGround(c);
			}
			else {
				// if you're in the air we do it
				// but if that results in entering the ground ..
				if (srv.inTheGround(c)) {
					int distance = 1;
					for (;;) {
						if (distance > FLOOR_DEFINITION_DISTANCE) {
							// it might not get us back into air (in which case
							// we are definitely entering ground from the side)
							c.y++;
							inGround = true;
							touchFloor = false;
							break;
						}
						if (!srv.inTheGround(c.copyAndMove(0, -distance))) {
							// or it might ... in which case we are touching
							// down
							if (distance > 1) {
								System.out.println("Recovered by jumping up " + distance);
							}
							c.y -= distance;
							if (!touchFloor) touchDown();
							break;
						}
						distance++;
					}
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
			vacuumFloor();
			jumpOnFire();
		}

		// when we are in the air
		// (which we might be fresh if we just went offTheEdge() above)
		if (!touchFloor) {
			// Jump off the air?
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

	/**
	 * A player who touches the floor is held down onto it by this method.
	 */
	private void vacuumFloor() {
		assert touchFloor;
		assert !inGround;
		assert !jumping;
		if (!srv.playerFall(c, 14)) {
			fallOff();
		}
	}

	private void doNormalMode() {
		if (mode == Mode.NORMAL) {
			// do normal mode!
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

	// ---------------------------------------------------------------------------
	// LADDER MODE

	private boolean testLadder(Coord where) {
		return srv.blockInfoIs(where, "ladderleft");
	}

	private boolean testLadder(int dx, int dy) {
		LadderInfo li = srv.getLadderInfo();
		return li != null && testLadder(c.copyAndMove(dx, dy + li.top))
				&& testLadder(c.copyAndMove(dx, dy + li.bottom));
	}

	private void perhapsStartLadderMode() {
		if (mode == Mode.NORMAL) {
			// alignment: [ ... 12 13 14] *15* [0 1 2 ... ]
			// snap: [ maxSnap ... 3 2 1] *0* [-1 -2 -3 ... -maxSnap ]

			int maxSnap;
			if (moveStick) {
				// work out maxSnap from our maximum speed
				// to ensure the player get's at least one
				// shot at getting on the ladder as he runs by
				maxSnap = (pvt.max() - 1) / 2;
			}
			else {
				maxSnap = LADDER_XSNAP_STATIONARY;
			}

			int snap = c.x;
			snap += maxSnap + 1;
			snap &= 15;
			snap = maxSnap - snap;

			// System.out.println("SNAP" + snap + "max" + maxSnap);
			if (snap >= -maxSnap && snap <= maxSnap && testLadder(snap, 0) && testStick(Joystick.DOWN | Joystick.UP)) {
				if (!ladderLatch) {
					if (testLadder(snap, getStickUpDownDelta())) {
						reset();
						mode = Mode.LADDER;
						c.x += snap;
						System.out.println("Ladder: on board!");
					}
					else {
						System.out.println("Ladder: run straight past");
					}
				}
			}
			else {
				ladderLatch = false;
			}
		}
	}

	private void doLadderMode() {
		if (mode == Mode.LADDER) {
			// do ladder!
			boolean moving = false;
			int delta = getStickUpDownDelta() * 2;
			MovementSlicer yslicer = new MovementSlicer(delta);
			while (yslicer.more()) {
				int n = yslicer.next(1);
				if (testLadder(0, n)) {
					c.y += n;
					moving = true;
				}
			}
			leaveLadder();
			setAnim("climb", moving);
		}
	}

	private void leaveLadder() {
		if ((!srv.inTheGround(c) && srv.inTheGround(c.copyAndMove(0, 1)))) {
			boolean leave = testStick(Joystick.LEFT | Joystick.RIGHT);
			System.out.println("Ladder: Disembarkation: " + leave);
			if (leave) {
				reset();
				touchFloor = true;
				ladderLatch = true;
			}
		}

		if (testStickAA(Joystick.FIRE)) {
			jump();
			ladderLatch = true;
		}
	}

	private boolean testForVerticalRope(int dy) {
		Coord where = c.copyAndMove(0, dy + VROPE_SNIFF_Y);
		if (!srv.blockInfoIs(where, "vrope")) return false;
		where.y += VROPE_SNIFF_YPLUS;
		return srv.blockInfoIs(where, "vrope");
	}

	// ---------------------------------------------------------------------------
	// ROPE MODE

	private void perhapsStartRopeMode() {
		if (mode == Mode.NORMAL && !touchFloor) {
			// start rope?
			if (!touchFloor && testStick(Joystick.DOWN | Joystick.UP) && testForVerticalRope(0)) {
				if (!ropeLatch) {
					goLeft = !goLeft;
					// block align:
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

	private boolean testForHorizontalRope(int dx) {
		Coord where = c.copyAndMove(dx, HROPE_SNIFF_Y);
		return srv.blockInfoIs(where, "hrope");
	}

	private void doRopeMode() {
		if (mode == Mode.ROPE_TWIST || mode == Mode.ROPE) {
			// do rope!
			// SCC7
			if (mode == Mode.ROPE) {
				boolean wannaTwistLeft = testStick(Joystick.LEFT) && !goLeft;
				boolean wannaTwistRight = testStick(Joystick.RIGHT) && goLeft;
				if (wannaTwistLeft || wannaTwistRight) {
					goLeft = !goLeft;
					mode = Mode.ROPE_TWIST;
				}
			}
			else {
				if (animPlayer.hasAnimEnded()) {
					mode = Mode.ROPE;
				}
			}

			int delta = getStickUpDownDelta() * 2;
			boolean nonTwistMoving = false;
			if (delta != 0 && testForVerticalRope(delta)) {
				c.y += delta;
				nonTwistMoving = true;
			}

			// exit the mode by pressing fire ..
			if (testStickAA(Joystick.FIRE)) {
				// and if you holding down ..
				if (testStick(Joystick.DOWN)) {
					// .. then you just drop
					reset();
					vely = -4;
				}
				else {
					jump();
				}
				ropeLatch = true;
				// the original didn't do this so must have
				// come out of rope mode facing the wrong way
				goLeft = !goLeft;
			}

			if (mode == Mode.ROPE) {
				setAnim(directionalAnimName("rope"), nonTwistMoving);
			}
			else {
				// always moving ...
				setAnim(directionalAnimName("ropetwist"), true);
			}

		}
	}

	// ---------------------------------------------------------------------------
	// MONKEY MODE

	private void perhapsStartMonkeyMode() {
		if (mode == Mode.NORMAL && !touchFloor) {
			// start monkey?
			// SCC5
			if (!touchFloor && testForHorizontalRope(0)) {
				if (vely >= 0 && !testStick(Joystick.DOWN) && !monkeyLatch) {
					// block align:
					c.y -= 2;
					c.y &= -16;
					c.y += 2;
					reset();
					mode = Mode.MONKEY;
					System.out.println("Monkey: Start");
				}
			}
			else {
				if (monkeyLatch) System.out.println("Monkey: clear");
				monkeyLatch = false;
			}
		}
	}

	private boolean monkeyAttempt(boolean left) {
		if (!testForHorizontalRope(directionalMovement(left, 8))) {
			// we used to fall off here -- but was that nice?
			// it sure kept the game flowing along but it wasn't obvious exactly
			// when it would happen and the consequences (if you were up high)
			// could be dire.
			// for now we just don't make the movement.
			return false;
		}
		goLeft = left;
		c.x += directionalMovement(left, 3);
		setAnim(directionalAnimName("monkey"), true);
		return true;
	}

	private void doMonkeyMode() {
		if (mode == Mode.MONKEY) {
			// do monkey!
			// SCC6
			boolean success = false;
			if (testStick(Joystick.LEFT)) {
				success |= monkeyAttempt(true);
			}
			else if (testStick(Joystick.RIGHT)) {
				success |= monkeyAttempt(false);
			}
			if (!success) {
				setAnim("monkeymid", true);
			}
			// exit the mode by pressing down ..
			if (testStickAA(Joystick.DOWN)) {
				reset();
				System.out.println("Monkey: end .. drop");
				monkeyLatch = true;
				c.y -= 4;
				vely = 4;
			}
			// or fire ..
			if (testStickAA(Joystick.FIRE)) {
				System.out.println("Monkey: end .. jump");
				jump();
				monkeyLatch = true;
			}
		}
	}

	// ---------------------------------------------------------------------------
	// MAIN MOVEMENT ROUTINE

	private void move2() {
		// remember our last position
		lc = c.copy();

		if (proofTimer != 0) proofTimer--;
		if (flashTimer != 0) flashTimer--;
		if (airJumpTimer != 0) airJumpTimer--;
		// stunTimer only decrements when touchFloor so isn't done here

		drawInWhite = (flashTimer & 15) > 9;

		if (stunTimer == 0) {
			perhapsStartMonkeyMode();
			perhapsStartRopeMode();
			perhapsStartLadderMode();
		}

		doMonkeyMode();
		doRopeMode();
		doLadderMode();

		doNormalMode();
	}

	// ---------------------------------------------------------------------------
	// OUR PUBLIC METHODS

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

	public void stun() {
		// if we not proof and not already stunned ..
		if (proofTimer == 0 && stunTimer == 0) {
			// reset(); from here
			jumpV(STUN_VELOCITY);
			stunTimer = STUN_TIME;
			moveStick = false;
		}
	}

	public void jump() {
		jumpV(JUMP_VELOCITY);
	}

	public void landOn(LiftAlien lift, int height) {
		reset();
		standingOn = lift;
		c.y = height;
		touchFloor = true;
	}

	@Override
	public void update() {
		// We need this method because the player is a pseudo Alien.
		// Actually, it's move() and draw() that are our entry points.
		// We're the only entity in the game with separate move and draw logic.
		assert false;
	}
}
