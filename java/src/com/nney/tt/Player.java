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
	private static final int RESTUN_PROOF_TIME = 25;
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
	 * 
	 * This is not as important as it sounds because if you "want" to get
	 * through a >{@link #FLOOR_DEFINITION_DISTANCE} pixel size step at floor
	 * level you'll need to jump through it sideways. Jumping through something
	 * so small at floor level will be hard because you have to jump <i>from</i>
	 * the floor and your jump return-velocity will be too big to allow such
	 * sneaky manoeuvres. Probably.
	 */
	private static final int FLOOR_DEFINITION_DISTANCE = 1;
	// 3 for now.
	// e.g. TTResource.map("w", 5) contains an example of such a spot.
	// There is a 3 pixel step because of single misplaced block.
	//

	// I think the original had FLOOR_DEFINITION_DISTANCE = 1

	// TODO: hollow out the masks for sign posts and trees.
	// We just want a single pixel running along the top of
	// each place where the player can stand.
	// Then the only issue is other platforms which doesn't happen much
	// so we can crank FLOOR_DEFINITION_DISTANCE up a bit?

	// TODO: reset the level if the player does manage to fall through
	// (not something we ever did in the original)

	/**
	 * A constant {@link #testSlide()} can return to say
	 * "the player isn't standing on a slide".
	 */
	private static final int NO_SLIDE = 9;

	private static final boolean CTC_VULNERABLE = false;

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
	 * Is the player moving the stick to the left or the right in
	 * {@link Mode#NORMAL}?
	 */
	private boolean moveStick;

	/**
	 * Is the player in the ground?
	 */
	private boolean inGround;

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
	private Mode mode = Mode.AIR;

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

	private int slideVel;

	private Coord ic;

	private boolean airSpin;

	private boolean flying;

	private boolean canFly;

	// ---------------------------------------------------------------------------
	// ENUMERATIONS

	enum Mode {
		WALK, LIFT, AIR, // <<-- these modes all run off the same xslicer
		SLIDE, STUN, MONKEY, ROPE, ROPE_TWIST, LADDER,
	}

	// ---------------------------------------------------------------------------
	// PRIVATE SUBROUTINES

	private void reset() {
		vely = 0;
		airJumpTimer = 0;
		stunTimer = 0;
		standingOn = null;
		airSpin = false;
		flying = false;
	}

	private void fallOff() {
		reset();

		mode = Mode.AIR;
		airJumpTimer = AIRJUMP_TIME;
		standingOn = null;
	}

	private void startModeWalk() {
		reset();
		mode = Mode.WALK;

		// it is important that we immediately check for slides
		// or the player could get off a rogue jump-off-a-slide
		// before we detect it later!
		perhapsStartSlideMode();
	}

	private void jumpV(int velocity) {
		if (standingOn != null) {
			velocity += standingOn.jumpBoost();
		}
		reset();
		vely = velocity;
		mode = Mode.AIR;
		airSpin = true;
	}

	private void jumpOnFire() {
		if (testStick(Joystick.FIRE)) {
			jump();
			System.out.println("Jump!");
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

	private int getStickDelta(int less, int more) {
		int delta = 0;
		if (testStick(less)) delta--;
		if (testStick(more)) delta++;
		return delta;
	}

	private int getStickUpDownDelta() {
		return getStickDelta(Joystick.UP, Joystick.DOWN);
	}

	private int getStickLeftRightDelta() {
		return getStickDelta(Joystick.LEFT, Joystick.RIGHT);
	}

	private boolean testStick(int j) {
		return srv.getStick().test(j) && stunTimer == 0;
	}

	private boolean testStickAA(int j) {
		return srv.getStick().testAntiAutofire(j) && stunTimer == 0;
	}

	private void applyGravity() {
		if (!flying || (srv.getFrameNumber() & 1) == 0) {
			vely = Math.min(vely + 1, 16);
		}
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

	private void setStandingAnim() {
		if (moveStick) {
			setAnim(directionalAnimName(""), true);
		}
		else {
			setAnim(directionalAnimName("stood"), true);
		}
	}

	private boolean normalVerticalMovement() {
		applyGravity();

		MovementSlicer yslicer = new MovementSlicer(vely);
		while (yslicer.more()) {
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
						c.y--;
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * A player who touches the floor is held down onto it by this method.
	 */
	private void vacuumFloor() {
		if (!srv.playerFall(c, 14)) {
			fallOff();
		}
	}

	// ---------------------------------------------------------------------------
	// WALK MODE

	private void doWalkModeX(MovementSlicer xslicer) {
		int n = xslicer.next(1);
		c.x += n;
		vacuumFloor();
	}

	private void doWalkModeY() {
		vacuumFloor();
		setStandingAnim();
	}

	// ---------------------------------------------------------------------------
	// AIR MODE

	private void doAirModeX(MovementSlicer xslicer) {
		int n = xslicer.next(1);
		c.x += n;
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
						break;
					}
					if (!srv.inTheGround(c.copyAndMove(0, -distance))) {
						// or it might ...
						// in which case we are touching down
						if (distance > 1) {
							System.out.println("Recovered by jumping up " + distance);
						}
						c.y -= distance;
						startModeWalk();
						break;
					}
					distance++;
				}
			}
		}

	}

	private void doAirModeY() {
		boolean flap = false;
		if (airJumpTimer != 0) {
			jumpOnFire();
		}
		else if (canFly && testStickAA(Joystick.FIRE)) {
			flying = true;
			vely = 0;
			flap = true;
		}
		if (normalVerticalMovement()) {
			startModeWalk();
		}

		if (flying) {
			setAnim(directionalAnimName("fly"), true);
			if (flap) {
				animPlayer.rewind();
			}
		}
		else {
			if (airSpin) {
				setAnim(directionalAnimName("jump"), true);
			}
			else {
				setAnim(directionalAnimName(""), false);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// LIFT MODE

	private void doLiftModeX(MovementSlicer xslicer) {
		int n = xslicer.next(1);
		c.x += n;
		if (!standingOn.horizontalOverlap(this)) {
			fallOff();
		}
	}

	private void doLiftModeY() {
		jumpOnFire();
		setStandingAnim();
	}

	// ---------------------------------------------------------------------------
	// STUN MODE

	private void startStunMode() {
		jumpV(STUN_VELOCITY);
		stunTimer = STUN_TIME;
		mode = Mode.STUN;
	}

	private void doStunMode() {
		if (mode == Mode.STUN) {
			if (normalVerticalMovement()) {
				setAnim("wobble", true);
				if (--stunTimer <= 0) {
					startModeWalk();
					proofTimer = RESTUN_PROOF_TIME;
				}
			}
			else {
				setAnim(directionalAnimName("jump"), true);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// SLIDE MODE

	private boolean perhapsStartSlideMode() {
		if (mode == Mode.WALK) {
			int slide = testSlide();
			if (slide != NO_SLIDE) {
				slideVel = ic.x - lc.x;
				System.out.println("Starting slide " + slideVel);
				mode = Mode.SLIDE;
				return true;
			}
		}
		return false;
	}

	private int signOf(int x) {
		if (x < 0) return -1;
		if (x > 0) return 1;
		return 0;

	}

	/**
	 * Is the player standing on a slide?
	 * 
	 * @return {@link #NO_SLIDE} if they are not on a slide. The x velocity
	 *         delta that the slide imparts per frame if they are on a slide.
	 */
	private int testSlide() {
		String s = srv.blockInfoHas(c, "slide:");
		if (s == null) return NO_SLIDE;
		return Integer.parseInt(s);
	}

	private void doSlideMode() {
		if (mode == Mode.SLIDE) {
			MovementSlicer xslicer = new MovementSlicer(slideVel);
			while (xslicer.more()) {
				c.x += xslicer.next(3);
				if (!srv.playerFall(c, 14)) {
					// we slid off an edge
					fallOff();
				}
			}
			updateSlideVel();

			// set our direction and we're done
			if (slideVel != 0) goLeft = slideVel < 0;
			setAnim(directionalAnimName("jump"), true);
		}
	}

	private void updateSlideVel() {
		int frm = srv.getFrameNumber();
		if ((frm & 1) == 0) {
			int slide = testSlide();
			if (slide == NO_SLIDE) {
				// not on something slippery
				// so slowly slow down
				if ((frm & 3) == 0) {
					slideVel -= signOf(slideVel);
					if (Math.abs(slideVel) <= pvt.max()) {
						// right! we've slowed to running speed on a
						// non-slippery surface
						mode = Mode.WALK;
						System.out.println("Slide: too slow quit");
						if (goLeft) {
							System.out.println("LEFT");
						}
						return;
					}
				}
			}
			else {
				// we are on something slippery
				// so slip!
				slideVel += slide;
				// and we get to influence it a bit with the joystick
				if ((frm & 7) == 0) {
					slideVel += getStickLeftRightDelta();
				}
			}
			// make sure we're not going to fast
			if (Math.abs(slideVel) > 16) {
				slideVel = signOf(slideVel) * 16;
			}

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
		if (mode == Mode.WALK || mode == Mode.AIR) {
			// alignment: [ ... 12 13 14] *15* [0 1 2 ... ]
			// snap: [ maxSnap ... 3 2 1] *0* [-1 -2 -3 ... -maxSnap ]

			int maxSnap;
			if (moveStick) {
				// work out maxSnap from our maximum speed
				// to ensure the player get's at least one
				// shot at getting on the ladder as he runs by
				maxSnap = (pvt.max() - 1) / 2;
				// TODO: thats wrong as it comes out at 0 given input of 1
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
				startModeWalk();
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
		if (mode == Mode.AIR) {
			// start rope?
			if (testStick(Joystick.DOWN | Joystick.UP) && testForVerticalRope(0)) {
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
		if (mode == Mode.AIR) {
			// start monkey?
			// SCC5
			if (testForHorizontalRope(0)) {
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
			boolean moving = false;
			if (testStick(Joystick.LEFT)) {
				moving |= monkeyAttempt(true);
			}
			else if (testStick(Joystick.RIGHT)) {
				moving |= monkeyAttempt(false);
			}
			if (!moving) {
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
		// remember our initial coordinate
		ic = c.copy();

		if (proofTimer != 0) proofTimer--;
		if (flashTimer != 0) flashTimer--;
		if (airJumpTimer != 0) airJumpTimer--;

		drawInWhite = (flashTimer & 15) > 9;

		perhapsStartMonkeyMode();
		perhapsStartRopeMode();
		perhapsStartLadderMode();
		perhapsStartSlideMode();

		// System.out.println("Mode:" + mode);
		if (mode == Mode.WALK || mode == Mode.LIFT || mode == Mode.AIR) {
			//
			// X
			//

			// These all run off the same MovementSlicer.
			// e.g. if we're running along the ground at 5 pix per frame
			// and after 1 pixel we run off the edge we still
			// have 4 pixels to go in the air.
			if (mode == Mode.LIFT) {
				assert standingOn != null;
				standingOn.moveMe(this);
			}

			int xmovement = getXDelta();
			MovementSlicer xslicer = new MovementSlicer(xmovement);
			while (xslicer.more()) {
				if (mode == Mode.WALK) {
					doWalkModeX(xslicer);
				}
				else if (mode == Mode.LIFT) {
					doLiftModeX(xslicer);
				}
				else if (mode == Mode.AIR) {
					doAirModeX(xslicer);
				}
				else {
					break;
				}
			}

			if (mode == Mode.WALK) {
				// The floor to air transition is done between X and Y movement.
				// Floor X, Air Y. This gives us a clean take off!
				// SCC9
				jumpOnFire();
			}

			//
			// Y
			//

			if (mode == Mode.WALK) {
				doWalkModeY();
			}
			else if (mode == Mode.LIFT) {
				doLiftModeY();
			}
			else if (mode == Mode.AIR) {
				doAirModeY();
			}
		}
		else {
			doStunMode();
			doSlideMode();
			doMonkeyMode();
			doRopeMode();
			doLadderMode();
		}

		// Coord delta = c.copy();
		// delta.sub(ic);
		// System.out.println("delta " + delta);

		// only now do we set our last coordinate from our initial coordinate
		// this way all the code in between has access to a meaningful lc value
		lc = ic;
	}

	// ---------------------------------------------------------------------------
	// OUR PUBLIC METHODS

	public void move() {
		move2();
	}

	@Override
	public void init() {
		setStandingAnim();
	}

	public void draw() {
		srv.queueSprite(c, playerSprite, drawInWhite);
	}

	public void giveShield() {
		proofTimer = 50 * 13;
		flashTimer = 50 * 12;
	}

	public void giveWings() {
		canFly = true;
	}

	public boolean isStunned() {
		return stunTimer != 0;
	}

	public boolean isReadyToBoardALift() {
		return mode == Mode.AIR && !inGround;
	}

	public void stun() {
		if (CTC_VULNERABLE) {
			if (proofTimer == 0 && stunTimer == 0) {
				startStunMode();
			}
		}
	}

	public void jump() {
		jumpV(JUMP_VELOCITY);
	}

	public void startLiftMode(LiftAlien lift, int height) {
		reset();
		mode = Mode.LIFT;
		standingOn = lift;
		c.y = height;
	}

	@Override
	public void update() {
		// We need this method because the player is a pseudo Alien.
		// Actually, it's move() and draw() that are our entry points.
		// We're the only entity in the game with separate move and draw logic.
		assert false;
	}

	public boolean checkInvisFall(Coord gem) {
		Coord diff = c.copy();
		diff.sub(gem);
		// diff = player - gem (i.e. positive if gem is above or left of the
		// player)

		// must be above but not too far above
		if (diff.y > 0 && diff.y < 100) {
			if (getStickLeftRightDelta() != signOf(diff.x)) {
				int dx = Math.abs(diff.x);
				if (dx > 75 && dx < 100) {
					return true;
				}
			}
		}
		return false;
	}
}
