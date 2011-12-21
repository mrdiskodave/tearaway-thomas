package com.nney.tt;

import com.nney.tt.aliens.Lift;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.ParsedJoystick;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.EdgeDetector;
import com.nney.tt.tinytools.FractionTracker;
import com.nney.tt.tinytools.Latch;

/**
 * Player movement.
 * 
 */
public class Player {
	/**
	 * If we fall below the line Y=lowerEdge then we're dead. The map has enough
	 * of a border on it that we do not have to detect this immediately. One
	 * test per frame is more than adequate.
	 */
	private final int lowerEdge;

	public Player(AlienServices srv, Anims playerAnims, Coord initialPosition, boolean initialGoLeft, int lowerEdge) {
		this.srv = srv;
		this.playersAnimations = playerAnims;
		this.lowerEdge = lowerEdge;
		this.cr = initialPosition.copy();
		this.goLeft = initialGoLeft;
		this.lc = initialPosition.copy();
		this.pp = new PlayerPosition(cr, srv);
		this.crw = cr;
	}

	private void setAnim(String name, boolean animate) {
		// System.out.println("setAnim() "+name+" "+animate);
		Anim anim = playersAnimations.find(name);
		animPlayer.changeAnimation(anim);
		Sprite s = animate ? animPlayer.nextFrame() : animPlayer.currentFrame();
		srv.registerPlayerSpriteForAlienColisions(cr, s);
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

	/**
	 * <p>
	 * There was a bug in the original where the player would get kicked up the
	 * screen by two pixels when moving upward from air to ground. This means
	 * jumps through ground (e.g. jumping through a tree-branch in order to land
	 * on it) would reach to 68 up pixels from the floor. A normal jump only
	 * reaches 66 pixels from the floor.
	 * 
	 * <p>
	 * I've decided <b>not</b> to include this bug but, instead, to give the
	 * player a JUMP_VELOCITY of -12.245f rather than -12. This means <b>all</b>
	 * jumps now reach 68 pixels.
	 */
	private static final float JUMP_VELOCITY = -12.245f;

	// TODO: reset the level if the player does manage to fall through
	// (not something we ever did in the original)
	// and there is a place where you can jump out of the level
	// pretty easily on "falling off a log"

	/**
	 * A constant {@link #testSlide()} can return to say
	 * "the player isn't standing on a slide".
	 */
	private static final int NO_SLIDE = 9;

	private static final boolean CTC_STUNABLE = true;

	// ---------------------------------------------------------------------------
	// FIELDS

	/**
	 * Where we are at. We expose this. We could copy it but, for speed we
	 * return it directly and require/trust that other classes only read it.
	 */
	private Coord cr;

	public Coord readOnlyPlayerPosition() {
		return cr;
	}

	/**
	 * Internally, the few times we change the player position we do through so
	 * this. It refers to the same thing that {@link #cr} does -- so this is
	 * only a kind of annotation.
	 */
	private Coord crw;

	/**
	 * Has a reference to {@link #cr} and handles most moving of it.
	 */
	private PlayerPosition pp;

	/**
	 * Our last coordinate.
	 */
	private Coord lc;

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
	private boolean goLeft;

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
	 * after they've run off an edge. This resolves any graphical ambiguity or
	 * timing ambiguity ("I pressed it!!") in the player's favour - making the
	 * whole thing play smoother.
	 */
	private int airJumpTimer;

	/**
	 * The player flashes between regular display and all whited out while this
	 * is non-zero.
	 */
	private int flashTimer;

	/**
	 * The player run's faster while this is non-zero. See
	 * {@link PlayerVelocityTable}.
	 */
	private int turboTimer;

	/**
	 * A lift, if we are standing on one, otherwise <code>null</code>.
	 */
	private Lift standingOn;

	/**
	 * Our Y velocity.
	 */
	private float vely;

	/**
	 * Cleared when you touch the floor (or a lift!). Incremented when you
	 * bounce on a head!
	 */
	private int headBounceCounter;

	/**
	 * What {@link Mode} are we in?
	 */
	private Mode mode = Mode.AIR;

	private Latch monkeyLatch = new Latch();
	private Latch ropeLatch = new Latch();
	private Latch ladderLatch = new Latch(3);

	private int slideVel;

	private Coord ic;

	private boolean airSpin;

	private boolean flying;

	private boolean canFly;

	private boolean hasStar;

	private int touchDownVel;

	private boolean flyingFlap;

	private int jdx;

	private int jdy;

	private EdgeDetector jfire = new EdgeDetector();

	/**
	 * The fractional part of our Y ordinate.
	 * 
	 * <p>
	 * {@link Coord} is all integers. This entire project runs in integer
	 * coordinates. The exception is Player jumping velocity and gravity which
	 * are both floats. This object keeps track of the "part less than 1.0f" of
	 * our Y ordinate so that everything else can stay as integers.
	 */
	private FractionTracker yFraction = new FractionTracker();

	// ---------------------------------------------------------------------------
	// ENUMERATIONS

	enum Mode {
		WALK, LIFT, AIR, // <<-- these modes all run off the same xslicer
		SLIDE, STUN, MONKEY, ROPE, ROPE_TWIST, LADDER,
	}

	// ---------------------------------------------------------------------------
	// PRIVATE SUBROUTINES

	// controls

	private boolean wantsToExitMode() {
		return jfire.pressed();
	}

	private boolean wantsToJump() {
		return jfire.current();
	}

	private boolean wantsToFly() {
		return jfire.pressed();
	}

	private boolean wantsToDrop() {
		return jdy > 0;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// -

	private void reset(Mode n) {
		vely = 0;
		airJumpTimer = 0;
		stunTimer = 0;
		standingOn = null;
		airSpin = false;
		flying = false;

		mode = n;
	}

	private void fallOff() {
		reset(Mode.AIR);

		airJumpTimer = AIRJUMP_TIME;
		standingOn = null;
	}

	private void startModeWalk() {
		reset(Mode.WALK);

		// if you jump off a ladder holding up (meaning: grip/climb ladder)
		// you won't grip (because of the latch) but this shouldn't go on
		// forever so we should clear the latch when you hit the ground.
		ladderLatch.clear();

		// it is important that we immediately check for slides
		// or the player could get a rogue jump-off-a-slide
		// before we detect it later!
		perhapsStartSlideMode();

		onSomething();
	}

	/**
	 * Called when you standing on something (lift or the floor).
	 */
	private void onSomething() {
		headBounceCounter = 0;
	}

	private void jumpV(float velocity) {
		if (mode == Mode.LIFT) {
			velocity += standingOn.lastFrameDelta().y;
		}
		reset(Mode.AIR);
		vely = velocity;
		airSpin = true;
	}

	private void jumpIfWanted() {
		if (wantsToJump()) {
			jump();
		}
	}

	private String directionalAnimName(String base) {
		return Anims.directionalAnimName(goLeft, base);
	}

	private int directionalMovement(boolean left, int x) {
		return left ? -x : x;
	}

	private float applyGravity(float v) {
		float g = 1;
		if (flying) g = 0.5f;
		return Math.min(v + g, 16);
	}

	private int getXDelta() {
		int d = jdx;
		if (d < 0) goLeft = true;
		if (d > 0) goLeft = false;
		int xdelta = pvt.next(d);
		return keepXDeltaOnScreen(xdelta);
	}

	private int keepXDeltaOnScreen(int xdelta) {
		Coord tp = cr.copy();
		tp.x += xdelta;
		srv.validatePlayerPosition(tp);
		xdelta = tp.x - cr.x;
		return xdelta;
	}

	private boolean normalVerticalMovement() {
		vely = applyGravity(vely);

		int yMove = yFraction.set(yFraction.get() + vely);

		MovementSlicer yslicer = new MovementSlicer(yMove);
		while (yslicer.more()) {
			int n = yslicer.next(1);
			pp.move(0, n);
		}
		if (vely > 0 && pp.isStanding()) {
			yFraction.set(0);
			return true;
		}
		return false;
	}

	// ---------------------------------------------------------------------------
	// AIR MODE

	private void doAirModeY() {
		if (airJumpTimer != 0) {
			jumpIfWanted();
		}
		else if (canFly && wantsToFly()) {
			flying = true;
			vely = 0;
			flyingFlap = true;
		}
		if (normalVerticalMovement()) {
			if (wantsToJump()) touchDownVel = (int) vely;
			startModeWalk();
		}
	}

	// ---------------------------------------------------------------------------
	// LIFT MODE

	private void doLiftModeX(MovementSlicer xslicer) {
		int n = xslicer.next(1);
		crw.x += n;
		if (!horizontalOverlap(standingOn)) {
			fallOff();
		}
	}

	// Y handled inline in move2()

	// ---------------------------------------------------------------------------
	// STUN MODE

	private void startStunMode(int t) {
		jumpV(STUN_VELOCITY);
		stunTimer = t;
		assert mode == Mode.AIR;
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
				assert mode == Mode.WALK;
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
		String s = srv.blockInfoHas(cr, "slide:");
		if (s == null) return NO_SLIDE;
		return Integer.parseInt(s);
	}

	private void doSlideMode() {
		if (mode == Mode.SLIDE) {
			MovementSlicer xslicer = new MovementSlicer(slideVel);
			while (xslicer.more()) {
				pp.move(xslicer.next(1), 0);
			}
			updateSlideVel();

			// set our direction and we're done
			if (slideVel != 0) goLeft = slideVel < 0;
			setAnim(directionalAnimName("jump"), true);

			if (!pp.isStanding()) {
				fallOff();
			}

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
					slideVel -= Integer.signum(slideVel);
					if (Math.abs(slideVel) <= pvt.max()) {
						// right! we've slowed to running speed on a
						// non-slippery surface
						System.out.println("Slide: too slow so quit");
						startModeWalk();
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
					slideVel += jdx;
				}
			}
			// make sure we're not going to fast
			if (Math.abs(slideVel) > 16) {
				slideVel = Integer.signum(slideVel) * 16;
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
		return li != null && testLadder(cr.copyAndAdd(dx, dy + li.top))
				&& testLadder(cr.copyAndAdd(dx, dy + li.bottom));
	}

	private void perhapsStartLadderMode() {
		if (mode == Mode.WALK || mode == Mode.AIR) {
			// alignment: [ ... 12 13 14] *15* [0 1 2 ... ]
			// snap: [ maxSnap ... 3 2 1] *0* [-1 -2 -3 ... -maxSnap ]

			int start = lc.x;
			int end = cr.x;
			if (!moveStick()) {
				start = cr.x - LADDER_XSNAP_STATIONARY - 1;
				end = cr.x + LADDER_XSNAP_STATIONARY;
			}

			// System.out.println(String.format("ladder: %s-%s %s", start, end,
			// lo));
			if (jdy != 0) {
				System.out.println(String.format("%s Ladder: want", srv.getFrameNumber()));
				int lo = computeLadderOption(start, end);
				int dx = lo - cr.x;
				if (lo > 0 && testLadder(dx, 0) && testLadder(dx, getLadderVerticalDelta())) {
					System.out.println(String.format("%s Ladder: can", srv.getFrameNumber()));
					if (ladderLatch.can(srv.getFrameNumber())) {
						System.out.println(String.format("%s Ladder: do", srv.getFrameNumber()));
						reset(Mode.LADDER);
						crw.x = lo;
						System.out.println("Ladder: on board!");
					}
				}
			}
		}
	}

	private int computeLadderOption(int start, int end) {
		// TODO: this can be done with math not repetition
		MovementSlicer ms = new MovementSlicer(end - start);
		while (ms.more()) {
			start += ms.next(1);
			if ((start & 15) == 15) return start;
		}
		return -1;
	}

	private boolean moveStick() {
		return jdx != 0;
	}

	private void doLadderMode() {
		if (mode == Mode.LADDER) {
			ladderLatch.set(srv.getFrameNumber());

			// do ladder!
			boolean moving = false;
			MovementSlicer yslicer = new MovementSlicer(getLadderVerticalDelta());
			while (yslicer.more()) {
				int n = yslicer.next(1);
				if (testLadder(0, n)) {
					crw.y += n;
					moving = true;
				}
			}

			// leave the ladder?
			boolean wantToWalkOffLadder = jdx != 0;
			if (wantToWalkOffLadder && canWalkOffLadder()) {
				startModeWalk();
			}
			else if (wantsToExitMode()) {
				jumpOrDrop();
			}

			setAnim("climb", moving);
		}
	}

	public int getLadderVerticalDelta() {
		return jdy * 2;
	}

	private boolean canWalkOffLadder() {
		return !srv.inTheGround(cr) && srv.inTheGround(cr.copyAndAdd(0, 1));
	}

	private boolean testForVerticalRope(int dy) {
		Coord where = cr.copyAndAdd(0, dy + VROPE_SNIFF_Y);
		if (!srv.blockInfoIs(where, "vrope")) return false;
		where.y += VROPE_SNIFF_YPLUS;
		return srv.blockInfoIs(where, "vrope");
	}

	// ---------------------------------------------------------------------------
	// ROPE MODE

	private void perhapsStartRopeMode() {
		if (mode == Mode.AIR) {
			// start rope?
			if (jdy != 0 && testForVerticalRope(0) && ropeLatch.can(srv.getFrameNumber())) {
				// The original flipped goLeft here and not on mode exit.
				// We don't flip it here but do flip it on mode exit.
				// i.e. goLeft means the opposite to us (in this mode)

				// block align:
				crw.x &= -Const.BLOCK_SIZE;
				crw.x += (Const.BLOCK_SIZE / 2);
				reset(Mode.ROPE);
			}
		}
	}

	private boolean testForHorizontalRope(int dx) {
		Coord where = cr.copyAndAdd(dx, HROPE_SNIFF_Y);
		return srv.blockInfoIs(where, "hrope");
	}

	private void doRopeMode() {
		if (mode == Mode.ROPE_TWIST || mode == Mode.ROPE) {
			ropeLatch.set(srv.getFrameNumber());

			// do rope!
			// SCC7
			if (mode == Mode.ROPE) {
				boolean wannaTwistLeft = jdx < 0 && !goLeft;
				boolean wannaTwistRight = jdx > 0 && goLeft;
				if (wannaTwistLeft || wannaTwistRight) {
					goLeft = !goLeft;
					assert mode == Mode.ROPE;
					mode = Mode.ROPE_TWIST;
				}
			}
			else {
				if (animPlayer.hasAnimEnded()) {
					assert mode == Mode.ROPE_TWIST;
					mode = Mode.ROPE;
				}
			}

			int delta = getLadderVerticalDelta();
			boolean moving = false;
			if (delta != 0 && testForVerticalRope(delta)) {
				crw.y += delta;
				moving = true;
			}

			// jump off the rope
			if (wantsToExitMode()) {
				jumpOrDrop();
				goLeft = !goLeft;
			}

			if (mode == Mode.ROPE) {
				setAnim(directionalAnimName("rope"), moving);
			}
			else {
				// always animating when twisting
				setAnim(directionalAnimName("ropetwist"), true);
			}
		}
	}

	private void jumpOrDrop() {
		// though if you are holding down ...
		if (wantsToDrop()) {
			// .. then you just drop
			reset(Mode.AIR);
			vely = -4;
		}
		else {
			// .. otherwise you jump
			jump();
		}
	}

	// ---------------------------------------------------------------------------
	// MONKEY MODE

	private void perhapsStartMonkeyMode() {
		if (mode == Mode.AIR) {
			if (testForHorizontalRope(0)) {
				if (vely >= 0) {
					if (monkeyLatch.can(srv.getFrameNumber())) {
						if (!wantsToDrop()) {
							// block align:
							crw.y -= 2;
							crw.y &= -Const.BLOCK_SIZE;
							crw.y += 2;
							reset(Mode.MONKEY);
							System.out.println("Monkey: Start");
						}
					}
				}
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
		crw.x += directionalMovement(left, 3);
		setAnim(directionalAnimName("monkey"), true);
		return true;
	}

	private void doMonkeyMode() {
		if (mode == Mode.MONKEY) {
			monkeyLatch.set(srv.getFrameNumber());

			// do monkey!
			// SCC6
			boolean moving = false;
			int d = jdx;
			if (d < 0) {
				moving |= monkeyAttempt(true);
			}
			if (d > 0) {
				moving |= monkeyAttempt(false);
			}
			if (!moving) {
				setAnim("monkeymid", true);
			}
			// exit the mode by pressing down ..
			if (wantsToDrop()) {
				reset(Mode.AIR);
				vely = 4;
				System.out.println("Monkey: end .. drop");
			}
			// or jumping off
			if (wantsToExitMode()) {
				System.out.println("Monkey: end .. jump");
				jump();
			}
		}
	}

	// ---------------------------------------------------------------------------
	// WALK, LIFT AND AIR MODES

	private void doWalkLiftAndAirModes() {
		//
		// X
		//

		if (mode == Mode.LIFT) {
			assert standingOn != null;
			crw.add(standingOn.lastFrameDelta());
		}

		// These all run off the same MovementSlicer.
		// e.g. if we're running along the ground at 5 pix per frame
		// and after 1 pixel we run off the edge we still
		// have 4 pixels to go in the air.
		int xmovement = getXDelta();
		MovementSlicer xslicer = new MovementSlicer(xmovement);
		while (xslicer.more()) {
			if (mode == Mode.WALK) {
				pp.move(xslicer.next(1), 0);
			}
			else if (mode == Mode.LIFT) {
				doLiftModeX(xslicer);
			}
			else if (mode == Mode.AIR) {
				pp.move(xslicer.next(1), 0);
			}
			else {
				break;
			}
		}

		if (mode == Mode.WALK || mode == Mode.LIFT) {
			// The floor to air transition is done between X and Y movement.
			// Floor X, Air Y. This gives us a clean take off!
			// SCC9
			jumpIfWanted();
		}

		//
		// Y movement
		//

		if (mode == Mode.WALK) {
			if (!pp.isStanding()) {
				fallOff();
			}
		}
		if (mode == Mode.AIR) {
			doAirModeY();
			// might change to Mode.WALK
		}
		//
		// Mode.LIFT isn't mentioned here because the LiftAlien moves us
		// directly

		//
		// WALK LIFT AIR animations
		//

		// every path *must* call setAnim()
		if (mode == Mode.AIR) {
			if (flying) {
				setAnim(directionalAnimName("fly"), true);
				if (flyingFlap) {
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
		else {
			if (moveStick()) {
				setAnim(directionalAnimName(""), true);
			}
			else {
				setAnim(directionalAnimName("stood"), true);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// MAIN MOVEMENT ROUTINE

	private void move2() {
		// System.out.println("Player:" + c);
		touchDownVel = 0;
		flyingFlap = false;

		// remember our initial coordinate
		ic = cr.copy();

		if (proofTimer != 0) proofTimer--;
		if (flashTimer != 0) flashTimer--;
		if (airJumpTimer != 0) airJumpTimer--;
		if (turboTimer != 0) turboTimer--;

		pvt.setSprint(turboTimer != 0);

		drawInWhite = (flashTimer & 15) > 9;

		perhapsStartMonkeyMode();
		perhapsStartRopeMode();
		perhapsStartLadderMode();
		perhapsStartSlideMode();

		if (mode == Mode.WALK) {
			if (srv.frameTest(2) && srv.blockInfoIs(cr.copyAndAdd(0, 1), "magic")) {
				srv.magicDust(cr.copyAndAdd(srv.randomness(17) - 8, 0));
			}
		}

		if (mode == Mode.WALK || mode == Mode.LIFT || mode == Mode.AIR) {
			doWalkLiftAndAirModes();
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

	public void move(ParsedJoystick parsedJoystick) {
		playerSprite = null;
		if (isLostOffTheBottom()) {
			setAnim(directionalAnimName(""), true);
		}
		else {
			jdx = parsedJoystick.x();
			jdy = parsedJoystick.y();
			jfire.next(parsedJoystick.fire());
			move2();
		}
		assert playerSprite != null;
	}

	public boolean isLostOffTheBottom() {
		return cr.y >= lowerEdge;
	}

	public void draw() {
		srv.drawSprite(cr, playerSprite, drawInWhite);
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

	public void stun() {
		if (CTC_STUNABLE) {
			if (proofTimer == 0 && stunTimer == 0) {
				startStunMode(STUN_TIME);
			}
		}
	}

	public void kill() {
		if (CTC_STUNABLE) {
			reset(Mode.STUN);
			stunTimer = Integer.MAX_VALUE;
		}
	}

	public boolean onArse() {
		return stunTimer < Integer.MAX_VALUE;
	}

	private void startLiftMode(Lift lift, int height) {
		reset(Mode.LIFT);
		standingOn = lift;
		crw.y = height;
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
	 * hits the ground but also that they intend (next frame) to jump up again.
	 * i.e. that the play is "bouncing" off the ground.
	 * 
	 * @return The velocity in pixels per frame or zero if didn't happen this
	 *         frame.
	 */
	public int getTouchDownVel() {
		return touchDownVel;
	}

	public boolean isStunned() {
		return stunTimer != 0;
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
		Coord diff = cr.copy();
		diff.sub(hidden);
		// diff = player - hidden
		// (i.e. positive if hidden thing is above or left of the player)

		// must be above but not too far above
		if (diff.y > 0 && diff.y < 100) {
			if (jdx != 0 && jdx != Integer.signum(diff.x)) {
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

	public boolean isHeadBouncePossible(int intrusion) {
		if (mode == Mode.AIR) {
			if (vely > 2) {
				if (wantsToJump()) {
					System.out.println("SpareY:" + intrusion + " <= " + vely + "+4");
					if (intrusion <= vely + 4) {
						return true;
					}
				}
			}
		}
		return false;
	}

	public int headBounce(boolean alienWillSurviveTheImpact) {
		proofTimer = 3;
		jump();

		if (alienWillSurviveTheImpact) {
			// well it isn't worth much then
			return 50;
		}

		// ahh - it's worth compound bonus!
		int answer = FATAL_HEAD_BOUNCE_BONUSES[headBounceCounter];
		if (headBounceCounter < FATAL_HEAD_BOUNCE_BONUSES.length - 1) {
			headBounceCounter++;
		}
		return answer;
	}

	private boolean horizontalOverlap(Lift lift) {
		return lift.horizontalOverlap(cr.x);
	}

	private boolean verticalCrossing(int landOn) {
		return lc.y < landOn && cr.y >= landOn;
	}

	public void performLiftBoarding(Lift caller, int landOn) {
		if (mode == Mode.AIR && horizontalOverlap(caller) && verticalCrossing(landOn)) {
			startLiftMode(caller, landOn);
		}
	}

	/**
	 * Change the player's position.
	 * 
	 * This is the <b>only</b> way to change the player's position from outside
	 * of this class.
	 * 
	 * @param teleportDestination
	 *            A new place to move the player to.
	 */
	public void teleportTo(Coord teleportDestination) {
		// copy the content over because 'pp' also holds a
		// reference to that particular 'c'
		cr.copyFieldsFrom(teleportDestination);
	}

	public void giveTurbo() {
		turboTimer = proofTimer = flashTimer = Integer.MAX_VALUE;
	}
}
