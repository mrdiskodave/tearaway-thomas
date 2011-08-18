package com.nney.tt;

import com.nney.tt.aliens.LiftAlien;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Joystick;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

public class Player {
	public Player(AlienServices srv, Anims playerAnims, Coord playerStart, boolean goLeft) {
		this.srv = srv;
		this.playersAnimations = playerAnims;
		this.c = playerStart.copy();
		this.goLeft = goLeft;
		this.lc = playerStart.copy();
	}

	private boolean testStick(int s) {
		return srv.getStick().test(s);
	}

	private boolean testStickJustPressed(int s) {
		return srv.getStick().testJustPressed(s);
	}

	private void setAnim(String name, boolean animate) {
//		System.out.println("setAnim() "+name+" "+animate);
		Anim anim = playersAnimations.find(name);
		animPlayer.changeAnimation(anim);
		Sprite s = animate ? animPlayer.nextFrame() : animPlayer.currentFrame();
		srv.registerPlayerSpriteForAlienColisions(c, s);
		playerSprite = s;
	}

	// ---------------------------------------------------------------------------
	// CONSTANTS

	static final int[] FATAL_HEAD_BOUNCE_BONUSES = { 200, 500, 1000, 2500 }; 

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

	// TODO: hollow out the masks for sign posts and trees.
	// We just want a single pixel running along the top of
	// each place where the player can stand.
	// Then the only issue is other platforms which doesn't happen much
	// so we can crank FLOOR_DEFINITION_DISTANCE up a bit?

	// TODO: reset the level if the player does manage to fall through
	// (not something we ever did in the original)
	// and there is a place where you can jump out of the level
	// pretty easily on "falling off a log"

	/**
	 * A constant {@link #testSlide()} can return to say
	 * "the player isn't standing on a slide".
	 */
	private static final int NO_SLIDE = 9;

	private static final boolean CTC_VULNERABLE = true;

	// ---------------------------------------------------------------------------
	// FIELDS

	/**
	 * Where we are at.
	 */
	public Coord c;

	/**
	 * Services we need from our environment.
	 */
	private AlienServices srv;

	/**
	 * The AnimPlayer plays animations (in this case it plays them for the
	 * Player, confusingly).
	 */
	private AnimPlayer animPlayer = new AnimPlayer();

	/**
	 * Our animations.
	 */
	private Anims playersAnimations;

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
	 * Cleared when you touch the floor (or a lift!).
	 * Incremented when you bounce on a head!
	 */
	private int headBounceCounter;

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

	private boolean hasStar;

	private boolean inTheGroundBefore;

	private int touchDownVel;

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

		onSomething();
	}

	/**
	 * Called when you standing on something (be a lift or the floor). 
	 */
	private void onSomething() {
		headBounceCounter = 0;
	}

	private void jumpV(int velocity) {
		if (mode == Mode.LIFT) {
			velocity += standingOn.getPlayerJumpBoost();
		}
		reset();
		vely = velocity;
		mode = Mode.AIR;
		airSpin = true;
	}

	private boolean wantsToExitModeByJumping() {
		return testStickJustPressed(Joystick.FIRE);
	}

	private boolean wantsToJump() {
		return testStick(Joystick.FIRE);
	}

	private void jumpOnFire() {
		if (wantsToJump()) {
			jump();
		}
	}

	private String directionalAnimName(String base) {
		return base + (goLeft ? "left" : "right");
	}

	private int directionalMovement(boolean left, int x) {
		return left ? -x : x;
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

	private int applyGravity(int v) {
		if (!flying || srv.frameTest(2, 1)) {
			return Math.min(v + 1, 16);
		}
		return v;
	}

	private int getXDelta() {
		int xdelta = 0;
		if (testStick(Joystick.LEFT)) {
			xdelta = -pvt.next();
			goLeft = true;
		}
		else if (testStick(Joystick.RIGHT)) {
			xdelta = pvt.next();
			goLeft = false;
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
		if (moveStick()) {
			setAnim(directionalAnimName(""), true);
		}
		else {
			setAnim(directionalAnimName("stood"), true);
		}
	}

	private boolean normalVerticalMovement() {
		vely = applyGravity(vely);

		MovementSlicer yslicer = new MovementSlicer(vely);
		while (yslicer.more()) {
			int n = yslicer.next(1);
			c.y += n;
			if (landingLights()) {
				return true;
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

	// Y handled inline in move2()

	// ---------------------------------------------------------------------------
	// AIR MODE

	/**
	 * Have we touched down?
	 * 
	 * A touch down happens on a sky-to-ground edge and with a pixel of sky
	 * above the aforementioned pixel of ground.
	 * 
	 * @return <code>true</code> (meaning "we've touched down") on
	 *         <code>false</code> meaning ("we are still in the air").
	 */
	private boolean landingLights() {
		// SCC2
		if (srv.inTheGround(c)) {
			// in the ground
			if (!inTheGroundBefore) {
				// for the first time!
				// ... what is above?
				c.y--;
				if (srv.inTheGround(c)) {
					inTheGroundBefore = true;
					// ground ... so we are entering the ground
					c.y++;
					// System.out.println("LL: entering ground");
					return false;
				}
				else {
					// sky! ... so we are touching down
					inTheGroundBefore = false;
					// System.out.println("LL: touching down");
					return true;
				}
			}
			// in the ground AGAIN
			return false;
		}
		else {
			// in the sky
			inTheGroundBefore = false;
			return false;
		}
	}

	private void doAirModeX(MovementSlicer xslicer) {
		int n = xslicer.next(1);
		c.x += n;
		if (landingLights()) {
			startModeWalk();
		}
	}

	private void doAirModeY() {
		boolean flap = false;
		if (airJumpTimer != 0) {
			jumpOnFire();
		}
		else if (canFly && testStickJustPressed(Joystick.FIRE)) {
			flying = true;
			vely = 0;
			flap = true;
		}
		if (normalVerticalMovement()) {
			if (wantsToJump()) touchDownVel = vely;
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
		if (!standingOn.amIStillOnThisLift(this)) {
			fallOff();
		}
	}

	// Y handled inline in move2()

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
					slideVel -= Math2.signOf(slideVel);
					if (Math.abs(slideVel) <= pvt.max()) {
						// right! we've slowed to running speed on a
						// non-slippery surface
						System.out.println("Slide: too slow quit");
						startModeWalk();
//						mode = Mode.WALK;
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
				slideVel = Math2.signOf(slideVel) * 16;
			}

		}
	}

	// ---------------------------------------------------------------------------
	// LADDER MODE

	private boolean testLadder(Coord where) {
		return srv.blockInfoIs(where, "ladderleft");
	}

	private boolean testLadder(int dx, int dy) {
		LadderInformation li = srv.getLadderInfo();
		return li != null && testLadder(c.copyAndAdd(dx, dy + li.top)) && testLadder(c.copyAndAdd(dx, dy + li.bottom));
	}

	private void perhapsStartLadderMode() {
		if (mode == Mode.WALK || mode == Mode.AIR) {
			// alignment: [ ... 12 13 14] *15* [0 1 2 ... ]
			// snap: [ maxSnap ... 3 2 1] *0* [-1 -2 -3 ... -maxSnap ]

			int maxSnap;
			if (moveStick()) {
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

	private boolean moveStick() {
		return testStick(Joystick.LEFT | Joystick.RIGHT);
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

			// leave the ladder?
			boolean wantToWalkOffLadder = testStick(Joystick.LEFT | Joystick.RIGHT);
			if (wantToWalkOffLadder && canWalkOffLadder()) {
				startModeWalk();
				ladderLatch = true;
			}
			else if (wantsToExitModeByJumping()) {
				jump();
				ladderLatch = true;
			}

			setAnim("climb", moving);
		}
	}

	private boolean canWalkOffLadder() {
		return !srv.inTheGround(c) && srv.inTheGround(c.copyAndAdd(0, 1));
	}

	private boolean testForVerticalRope(int dy) {
		Coord where = c.copyAndAdd(0, dy + VROPE_SNIFF_Y);
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
					c.x &= -Const.BLOCK_SIZE;
					c.x += (Const.BLOCK_SIZE / 2);
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
		Coord where = c.copyAndAdd(dx, HROPE_SNIFF_Y);
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

			// jump off the rope
			if (wantsToExitModeByJumping()) {
				// though if you are holding down ...
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
					c.y &= -Const.BLOCK_SIZE;
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
			if (testStickJustPressed(Joystick.DOWN)) {
				reset();
				System.out.println("Monkey: end .. drop");
				monkeyLatch = true;
				c.y -= 4;
				vely = 4;
			}
			// or jumping off
			if (wantsToExitModeByJumping()) {
				System.out.println("Monkey: end .. jump");
				jump();
				monkeyLatch = true;
			}
		}
	}

	// ---------------------------------------------------------------------------
	// MAIN MOVEMENT ROUTINE

	private void move2() {
		touchDownVel = 0;

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

		if (mode == Mode.WALK) {
			if (srv.frameTest(2, 1) && srv.blockInfoIs(c, "magic")) {
				srv.magicDust(c.copyAndAdd(srv.randomness(17) - 8, 0));
			}
		}

		if (mode == Mode.WALK || mode == Mode.LIFT || mode == Mode.AIR) {
			//
			// X
			//

			if (mode == Mode.LIFT) {
				assert standingOn != null;
				standingOn.movePlayer(this);
			}

			// These all run off the same MovementSlicer.
			// e.g. if we're running along the ground at 5 pix per frame
			// and after 1 pixel we run off the edge we still
			// have 4 pixels to go in the air.
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

			if (mode == Mode.WALK || mode == Mode.LIFT) {
				// The floor to air transition is done between X and Y movement.
				// Floor X, Air Y. This gives us a clean take off!
				// SCC9
				jumpOnFire();
			}

			//
			// Y
			//

			if (mode == Mode.WALK) {
				vacuumFloor();
				setStandingAnim();
			}
			if (mode == Mode.LIFT) {
				setStandingAnim();
			}
			if (mode == Mode.AIR) {
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

	private void jump() {
		jumpV(JUMP_VELOCITY);
	}

	// ---------------------------------------------------------------------------
	// OUR PUBLIC METHODS

	// frame-loop calls
	//

	public void move() {
		move2();
	}

	public void draw() {
		srv.drawSprite(c, playerSprite, drawInWhite);
	}

	// gifts
	//

	public void giveStar() {
		hasStar = true;
	}

	public boolean gotStar() {
		return hasStar;
	}

	public void giveShield() {
		proofTimer = Const.FPS * 13;
		flashTimer = Const.FPS * 12;
	}

	public void giveWings() {
		canFly = true;
	}

	// actions
	//

	public void resetTo(Coord coord) {
		reset();
		c = coord;
	}

	public void stun() {
		if (CTC_VULNERABLE) {
			if (proofTimer == 0 && stunTimer == 0) {
				startStunMode();
			}
		}
	}

	public void startLiftMode(LiftAlien lift, int height) {
		reset();
		mode = Mode.LIFT;
		standingOn = lift;
		c.y = height;
		onSomething();
	}

	// enquires
	//

	/**
	 * How hard did we bounce off the ground?
	 * 
	 * <p>
	 * The result is for <b>this frame only</b> so you have to keep asking if
	 * you don't want to miss it. The requirement is not just that the player
	 * hits the ground but that they intend (next frame) to jump up again.
	 * 
	 * @return The velocity in pixels per frame with which we bounced (or zero
	 *         if we didn't).
	 */
	public int getTouchDownVel() {
		return touchDownVel;
	}

	public boolean isStunned() {
		return stunTimer != 0;
	}

	public boolean isReadyToBoardALift() {
		return mode == Mode.AIR;
	}

	/**
	 * Does the players movement prompt the given hidden object to appear?
	 * 
	 * Lots of power-ups and other cool things are hidden away in this fashion.
	 * 
	 * @param hidden
	 *            The coordinates of the hidden object.
	 * @return Either <code>true</code> (meaning "yes, it appears") or
	 *         <code>false</code> (meaning "no, it remains hidden").
	 */
	public boolean checkReveal(Coord hidden) {
		// SCC1
		Coord diff = c.copy();
		diff.sub(hidden);
		// diff = player - hidden
		// (i.e. positive if hidden thing is above or left of the player)

		// must be above but not too far above
		if (diff.y > 0 && diff.y < 100) {
			// must be moving towards
			int d = getStickLeftRightDelta();
			if (d != 0 && d != Math2.signOf(diff.x)) {
				// and must be the correct distance in front
				int dx = Math.abs(diff.x);
				if (dx > 75 && dx < 100) {
					// then it is revealed!
					return true;
				}
			}
		}
		return false;
	}

	public void boost(int i) {
		jumpV(i);
	}

	public boolean isHeadBouncePossible(int consideredInTearaway) {
		if (mode == Mode.AIR) {
			if (vely > 6) {
				if (wantsToJump()) {
					System.out.println("SpareY:" + consideredInTearaway + " <= "+vely+"+4");
					if (consideredInTearaway <= vely+4) {
						return true;
					}
				}
			}
		}
		return false;
	}

	public int headBounce(boolean alienWillSurviveTheImpact) {
		proofTimer = 1;
		jump();
		
		if (alienWillSurviveTheImpact) {
			// well it isn't worth much then
			return 100;
		}
		
		// ahh - it's worth compound bonus!
		int answer = FATAL_HEAD_BOUNCE_BONUSES[headBounceCounter]; 
		if (headBounceCounter<FATAL_HEAD_BOUNCE_BONUSES.length-1) {
			headBounceCounter++;
		}
		return answer;
	}
}

// TODO: 99: it does look like I can land on stuff (from the side)
// while still planly going upwards ..
// take vely into account...?
