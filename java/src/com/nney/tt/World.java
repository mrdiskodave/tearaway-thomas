package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BooleanSupplier;
import java.util.function.IntConsumer;
import java.util.function.Supplier;

import com.nney.coroutines.Coroutine;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.FallingAlien;
import com.nney.tt.aliens.GemAlien;
import com.nney.tt.aliens.IceGemAlien;
import com.nney.tt.aliens.LiftAlien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.MapBoundsAlien;
import com.nney.tt.aliens.PlayerAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.KeyEvent;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.ParsedJoystickImpl;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.osd.HeadUpDisplay;
import com.nney.tt.osd.OsdParser;
import com.nney.tt.osd.StatusDisplay;
import com.nney.tt.osd.StatusScreen;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.AudioHub;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.LineInfo;
import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.Countdown;
import com.nney.tt.tinytools.EdgeDetector;
import com.nney.tt.tinytools.Latch;
import com.nney.tt.tinytools.SlowBoolean;
import com.nney.utils.ListUtil;
import com.nney.utils.Math2;

public class World implements AlienServices, Disposable {
	static public class ExitException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

	/** How a call to {@link #playLevel()} ended. */
	public enum Outcome {
		/** Level done; {@link OuterWorld#levelNumber} has moved on. */
		COMPLETED,
		/** Lost a life; play the same level again. */
		LIFE_LOST,
		/** Lost the last life. */
		GAME_OVER,
		/** Developer pressed Esc: the map editor has been launched. */
		TO_MAPPER,
		/** A demo ran its course (or the demo player died or finished). */
		DEMO_OVER,
		/** Someone pressed fire during a demo: they want to play. */
		DEMO_INTERRUPTED
	}

	/**
	 * Watches a demo, frame by frame, and may draw over it (e.g. the title
	 * sequence).
	 */
	public interface DemoDirector {
		/**
		 * Called once a frame after the game has drawn everything.
		 * 
		 * @return <code>false</code> to end the demo.
		 */
		boolean frame();
	}

	private Outcome outcome = Outcome.COMPLETED;

	/** Non-null while playing a demo: where the "player's" input comes from. */
	private Joystick demoJoystick;

	private DemoDirector demoDirector;

	/** Has the real fire button been up since the demo began? */
	private boolean demoFireWasUp;

	private void exit(Outcome o) {
		outcome = o;
		throw new ExitException();
	}

	private boolean isDemo() {
		return demoJoystick != null;
	}

	/**
	 * Play this level as a demo: no intro or outro, input from a recording,
	 * ends when the director says so, when the "player" dies or finishes, or
	 * when someone presses fire. Music is left to the caller.
	 */
	public void configureDemo(Joystick recording, DemoDirector director) {
		demoJoystick = recording;
		demoDirector = director;
		configuredPerformIntro = false;
	}

	// 36 0x38,3c 3a 00
	//
	// lvl13 : 0x32 spinning lift

	// 8 map+code: needs lift 0
	// 9 map+code: needs lift 0
	// 10 ok
	// 11 map+code: needs lift 101
	// 12 map: secret area visible
	// 13 map|code: fall through??
	// 14 ok
	// 15 the gallery:
	// -- map: wall priority

	// TODO: code balloon man

	// Disposable:
	private HeadUpDisplay hud;

	private AlienInfoMap alienInfoMap;

	private Horizon horizon;

	private String worldName;

	private ScreenPosition scr;

	/**
	 * Compile time configuration: the screen follows the player <b>exactly</b>.
	 */
	private static final boolean CTC_HARD_SCROLLING = false;

	/**
	 * The same seed as the original (init_game: move.w #$a713,seed) so that,
	 * like the original, a level plays out identically given identical input.
	 * That's what makes recorded demos possible. A new World is made for each
	 * level (and each life), so this restarts every time.
	 */
	public static final long RANDOM_SEED = 0xa713;

	final private Random rnd = new Random(RANDOM_SEED);

	private Player player;

	private GameMap gameMap;

	private GameAlienTracker alienTracker;

	private int frameNumber;

	/**
	 * Player sprite.
	 */
	private Sprite ttSprite;

	/**
	 * Player sprite top level (i.e. incorporates handle subtraction).
	 */
	private Coord playerSpriteTopLeft;

	private int timeRemainingInFrames;

	private int gemsNeeded;

	private int gemsTotal;

	private int gemsCollected;

	private boolean collisionDetection = true;

	/**
	 * A record of where (and how) we've put a {@link Sprite}.
	 */
	class SpriteRecord {
		private final Coord c;
		private final Sprite s;
		private final boolean drawInWhite;
		private final float opacity;
		/** Thomas rather than an alien. */
		private final boolean isPlayer;

		SpriteRecord(Coord c, Sprite s, boolean drawInWhite, float opacity, boolean isPlayer) {
			this.c = c.copy();
			this.s = s;
			this.drawInWhite = drawInWhite;
			this.opacity = opacity;
			this.isPlayer = isPlayer;
		}
	}

	/**
	 * <p>
	 * Pausing it a bit complicated:
	 * 
	 * <p>
	 * The aliens update their state <b>and</b> draw themselves in one method:
	 * {@link Alien#update()}. We are expected just draw the screen every frame
	 * when the game is paused but there is no method on {@link Alien} to just
	 * draw it. This the legacy reason being that all the update methods are
	 * modelled on their 68000 originals.
	 * 
	 * <p>
	 * Solution: we call {@link Alien#update()} (which'll have the unfortunate
	 * effect of moving the alien by one frame) but we're really doing it to
	 * capture a recording of where all the {@link Sprite}s get drawn. Then we
	 * just play it back while we're paused without any further calls to
	 * {@link Alien#update()}.
	 * 
	 * <p>
	 * ORRR.... we use this recording mechanism all the time perhaps? That would
	 * decouple updating and actually drawing. Aliens would need to be
	 * update()ed in Alien.depth order and we'd have a recording sitting around
	 * for whenever we needed it.
	 * 
	 * <p>
	 * ORRRR..... we change the calling model so that we are not expected to
	 * draw the screen every frame!
	 * 
	 * <p>
	 * This is where we store the recording.
	 */
	private final ArrayList<SpriteRecord> recording = new ArrayList<SpriteRecord>();

	private ScriptWriter scriptWriter;

	private ScriptReader scriptReader;

	/**
	 * Pressing the pause key.
	 */
	private EdgeDetector pauseKey = new EdgeDetector();

	/**
	 * Pressing fire.
	 */
	boolean firePressed;

	// ---------------------------------------------------------------------------

	// Disposable:
	private StatusDisplay statusDisplay;

	private boolean record;

	// Disposable:
	private DisposableField<StatusScreen> statusScreen = new DisposableField<StatusScreen>();

	private Aperture hole;

	private Fade dimFade;

	private Fade totalFade;

	private Coroutine cr;

	private static final int TELEPORT_TIME = 20;

	private int teleportTimer;

	private final Latch teleportLatch = new Latch();

	private Coord teleportDestination;

	private BlockSet blockSet;

	private OuterWorld ow;

	private GraphicsContext gc;

	private AudioHub ah;

	private Joystick joystick;

	private Keyboard keyboard;

	private Fonts fonts;

	private AnimsPool animsPool;

	private Coord configuredPlayerStart;

	private String configuredMapText;

	private boolean isPlayerPresent = true;

	private Coord whereWeExitedTheLevel;

	private LevelInfo levelInfo;

	private boolean configuredCalledFromMapper;

	private boolean didScroll;

	private ParsedJoystickImpl parsedJoystick = new ParsedJoystickImpl();

	private boolean configuredPerformIntro = true;

	private String configuredScriptDestination;

	private boolean configuredSeeMasks;

	private boolean configuredSeeHidden;

	static final private boolean CTC_MEASURE_JUMP_HEIGHT = false;

	private int smallestY;

	private List<MapBoundsAlien> mbas;

	private Countdown delayedFinish = new Countdown();

	private Mode mode;

	private int lowerEdge;

	private boolean levelCompleted;

	// ---------------------------------------------------------------------------
	// THE SEQUENCES AROUND A LEVEL (as the original: one thing at a time)

	/** fade_out and fade_in in s195: 16 steps, one a frame. */
	private static final int FADE_FRAMES = 16;

	/** wait4fire in s195 gives up after 3 seconds. */
	private static final int WAIT4FIRE = 3 * Const.FPS;

	/** Collect every gem without losing a life on the level. */
	private static final int PERFECT_BONUS = 10000;

	/** Text screens use the bitplanes the aliens are drawn in, so they hide them. */
	private boolean aliensHidden;

	/** Set while Thomas (rather than an alien) is being drawn. */
	private boolean drawingPlayer;

	/** A life has gone (time ran out) since this level began. */
	private boolean lifeLostHere;

	/** The level a perfect collection is possible on (not challenges or fruit). */
	private boolean normalLevel;

	/** Did the level just completed earn the perfect bonus? */
	private boolean perfectLevel;

	private boolean configuredWorldLogo = true;

	private String configuredDemoMusic;

	private BooleanSupplier demoInterruptible = () -> true;

	private Supplier<String[]> configuredEnding;

	public World(OuterWorld ow) {
		this.ow = ow;
		this.gc = ow.gc;
		this.ah = ow.ah;
		this.scr = new ScreenPosition(gc.screenWidth(), gc.screenHeight(), new Coord(50, 64));
		this.joystick = ow.joystick;
		this.keyboard = ow.keyboard;
		this.fonts = ow.fonts;
		this.animsPool = ow.animsPool;
	}

	// ---------------------------------------------------------------------------
	// MOSTLY SERVICES FOR THE ALIEN IMPLEMENTATIONS TO CALL

	@Override
	public int randomness(int n) {
		return rnd.nextInt(n);
	}

	private int getBlock(Coord c) {
		int x = c.x >> Const.BLOCK_SHIFT;
		int y = c.y >> Const.BLOCK_SHIFT;
		return gameMap.fastGetBlock(x, y);
	}

	@Override
	public boolean inTheGround(Coord c) {
		return inTheGround(c.x, c.y);
	}

	@Override
	public boolean inTheGround(int x, int y) {
		int block = gameMap.fastGetBlock(x >> Const.BLOCK_SHIFT, y >> Const.BLOCK_SHIFT);
		return blockSet.maskHolder.inTheGround(block, x & Const.BLOCK_MASK, y & Const.BLOCK_MASK);
	}

	/**
	 * What is there?
	 * 
	 * @param c
	 *            The pixel location being queried.
	 * @return The kind of block that is there. e.g. "magic" or "ladder" or any
	 *         text string used in the configuration of the
	 *         {@link BlockInformation} object.
	 */
	private String getBlockInfo(Coord c) {
		int block = getBlock(c);
		return blockSet.getBlockInfo(block);
	}

	@Override
	public boolean blockInfoIs(Coord c, String name) {
		String s = getBlockInfo(c);
		boolean answer = s != null && s.equals(name);
		// if (answer) {
		// System.out.println(String.format("Is %s is %s", getBlock(c), name));
		// }
		return answer;
	}

	@Override
	public String blockInfoHas(Coord c, String prefix) {
		String s = getBlockInfo(c);
		if (s == null || !s.startsWith(prefix)) return null;
		return s.substring(prefix.length());
	}

	@Override
	public boolean playerFall(Coord where, int fallMax) {
		// if we are in the ground ..
		if (inTheGround(where)) {
			// raise until we are not
			do {
				where.y--;
			} while (inTheGround(where));
			return true;
		}
		else {
			int givenY = where.y;
			for (;;) {
				// otherwise fall
				where.y++;
				// but once we're in the ground
				if (inTheGround(where)) {
					// back out by one
					where.y--;
					// and we're done!
					return true;
				}
				// UNLESS we blow our maximum fallDistance
				if (--fallMax <= 0) {
					where.y = givenY;
					return false;
				}
			}
		}
	}

	@Override
	public void oneLessGem(int score, Coord noticeLocation) {
		if (isExitOpen()) {
			score *= 2;
		}
		gemsCollected++;
		awardScore(score, noticeLocation);
		playSoundEffect("gem");
	}

	@Override
	public boolean isExitOpen() {
		return mode.hasExit() && gemsCollected >= gemsNeeded;
	}

	// ---------------------------------------------------------------------------
	// DRAWING

	@Override
	final public void drawSprite(Coord c, Sprite s) {
		drawSprite(c, s, false);
	}

	@Override
	final public void drawSprite(Coord c, final Sprite s, boolean drawWhite) {
		drawSprite(c, s, drawWhite, 1f);
	}

	@Override
	final public void drawSpriteTranslucent(Coord c, Sprite s, float opacity) {
		drawSprite(c, s, false, opacity);
	}

	private void drawSprite(Coord c, final Sprite s, boolean drawWhite, float opacity) {
		if (record) {
			recording.add(new SpriteRecord(c, s, drawWhite, opacity, drawingPlayer));
		}
		else if (!aliensHidden || drawingPlayer) {
			directDrawSprite(c, s, drawWhite, opacity);
		}
	}

	private void directDrawSprite(Coord c, final Sprite s, boolean drawWhite, float opacity) {
		Coord screen = scr.position();
		final int x = c.x - screen.x;
		final int y = c.y - screen.y;
		if (opacity < 1f) {
			s.drawByHandleTranslucent(x, y, opacity);
		}
		else {
			s.drawByHandle(x, y, drawWhite);
		}
	}

	@Override
	public void registerPlayerSpriteForAlienColisions(Coord c, Sprite s) {
		playerSpriteTopLeft = c.copy();
		playerSpriteTopLeft.x -= s.handleX;
		playerSpriteTopLeft.y -= s.handleY;
		ttSprite = s;
	}

	/** What the player's joystick says this frame (for aliens that ask). */
	private int currentJoystick;

	@Override
	public int getJoystick() {
		return currentJoystick;
	}

	@Override
	public int getBlockNumber(Coord c) {
		return getBlock(c);
	}

	/** Made afresh for each attempt, as the original did in its level setup. */
	private final TearawayLetters letters = new TearawayLetters();

	@Override
	public TearawayLetters getLetters() {
		return letters;
	}

	@Override
	public boolean isChallenge() {
		return levelInfo.title.startsWith("challenge") || levelInfo.mode.startsWith("challenge");
	}

	@Override
	public void setTimeRemaining(int seconds) {
		timeRemainingInFrames = seconds * Const.FPS + Const.FPS - 1;
	}

	@Override
	public Coord getPlayerPosition() {
		return player.readOnlyPlayerPosition();
	}

	@Override
	public void validatePlayerPosition(Coord c) {
		c.x = scr.keepPlayerXInMap(c.x);

	}

	@Override
	public boolean keepInMap(Coord c) {
		return scr.keepInMap(c);
	}

	@Override
	public int getFrameNumber() {
		return frameNumber;
	}

	@Override
	public boolean collideBoxWithPlayer(Box box) {
		int diffX = player.readOnlyPlayerPosition().x;
		int diffY = player.readOnlyPlayerPosition().y;

		// drawAbsoluteDebugText(new Coord(0, 50), String.format("%s %s,%s",
		// box, diffX, diffY));
		if (diffX >= box.left - 8) {
			if (diffX <= box.right + 8) {
				// drawAbsoluteDebugText(new Coord(0, 70),
				// String.format("X overlap"));
				if (diffY >= box.top) {
					if (diffY <= box.bottom + 30) {
						// drawAbsoluteDebugText(new Coord(0, 90),
						// String.format("Y overlap"));
						return collisionDetection;
					}
				}
			}
		}
		return false;
	}

	@Override
	public boolean collideBoxWithPlayerHandle(Box box) {
		int diffX = player.readOnlyPlayerPosition().x;
		int diffY = player.readOnlyPlayerPosition().y;
		if (diffX >= box.left) {
			if (diffX <= box.right) {
				if (diffY >= box.top) {
					if (diffY <= box.bottom) {
						return collisionDetection;
					}
				}
			}
		}
		return false;
	}

	private boolean hbCollide(Coord alienPos, Sprite alienSprite, int h) {
		int dx = alienPos.x - alienSprite.handleX - playerSpriteTopLeft.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - (playerSpriteTopLeft.y - h);
			if (dy < ttSprite.h && dy > (-alienSprite.h)) {
				if (dy < 0) {
					return LineInfo.collide(alienSprite.lineInfo, ttSprite.lineInfo, -dy, dx);
				}
				else {
					return LineInfo.collide(ttSprite.lineInfo, alienSprite.lineInfo, dy, -dx);
				}
			}
		}
		return false;
	}

	private boolean hbCollides(Coord alienPos, Sprite[] alienSprites, int h) {
		for (Sprite alienSprite : alienSprites) {
			if (hbCollide(alienPos, alienSprite, h)) return true;
		}
		return false;
	}

	@Override
	public void secretBonusFound() {
		ow.secretBonusFound = true;
	}

	@Override
	public boolean headBounce(Alien alien, Sprite... alienSprites) {
		Coord alienPos = alien.getLocation();

		// this can surely be optimised
		// e.g. if hbCollide() just ran bottom-up rather
		// than top-down that would help
		int h = 1;
		while (hbCollides(alienPos, alienSprites, h)) {
			h++;
		}

		if (player.isHeadBouncePossible(h)) {
			playSoundEffect("headbounce");
			Anim frightAnim = alien.anims.mightFind("fright");
			boolean willSurvive = frightAnim == null;
			int headScore = player.headBounce(willSurvive);
			int raiseScoreNoticeBy = alienSprites[0].handleY + 10;
			if (willSurvive) {
				awardScore(headScore, new Coord(alienPos.x, alienPos.y - raiseScoreNoticeBy));
			}
			else {
				alien.done();
				FallingAlien fa = new FallingAlien(alienPos, headScore, raiseScoreNoticeBy, frightAnim);
				attachConnectLoad(fa);
			}
			return true;
		}

		// no head bounce :(
		player.stun();
		return false;
	}

	@Override
	public boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - playerSpriteTopLeft.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - playerSpriteTopLeft.y;
			if (dy < ttSprite.h && dy > (-alienSprite.h)) {
				if (dy < 0) {
					return LineInfo.collide(alienSprite.lineInfo, ttSprite.lineInfo, -dy, dx) && collisionDetection;
				}
				else {
					return LineInfo.collide(ttSprite.lineInfo, alienSprite.lineInfo, dy, -dx) && collisionDetection;
				}
			}
		}
		return false;
	}

	@Override
	public Player getThePlayer() {
		return player;
	}

	@Override
	public LadderInformation getLadderInfo() {
		return blockSet.getLadderInfo();
	}

	@Override
	public boolean frameTest(int mask) {
		return (getFrameNumber() & (mask - 1)) == 0;
	}

	@Override
	public boolean fall(Coord c, int fallSpeed) {
		for (int x = 0; x < fallSpeed; x++) {
			c.y++;
			if (inTheGround(c)) {
				c.y--;
				return true;
			}
		}
		return false;
	}

	@Override
	public void awardScore(int amount, Coord location) {
		ow.score += amount;
		if (location != null) {
			attachConnectLoad(new ScoreNoticeAlien(amount, location.copy()));
		}
	}

	@Override
	public void magicDust(Coord location) {
		attachConnectLoad(new MagicDustAlien(location.copy()));
	}

	@Override
	public void addAlien(Alien a) {
		attachConnectLoad(a);
	}

	@Override
	public void addAlien(String name, Coord where) {
		Alien a = alienInfoMap.instantiateAttach(alienInfoMap.getByName(name));
		a.resetTo(where.copy());
		a.connect(animsPool);
		load(a);
	}

	// ---------------------------------------------------------------------------
	// ALIEN LIFECYCLE

	/**
	 * We've just <code>new</code>ed the given alien rather than creating it
	 * from a typeCode. Fill in all it's bits and pieces.
	 * 
	 * @param alien
	 *            The {@link Alien} to complete.
	 */
	private void attachConnectLoad(Alien alien) {
		alienInfoMap.attach(alien);
		alien.connect(animsPool);
		load(alien);
	}

	public void load(Alien alien) {
		alienTracker.delayedAdd(alien);
	}

	// ---------------------------------------------------------------------------

	private void updateList(List<Alien> alienList) {
		for (Iterator<Alien> alienIterator = alienList.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			alien.freezeBounds = null;
			alien.update();

			// Box fb = alien.freezeBounds;
			// if (fb!=null) {
			// Box s = fb.sub2(getScreenPosition());
			// gc.fillRectangle(s.left, s.top, s.width(), s.height(),
			// 0x80ff0000);
			// }

			if (alien.remove) {
				alienIterator.remove();
			}
		}
	}

	private void updateTheAliens() {
		recording.clear();

		// add fresh aliens
		Box screenBox = scr.box();
		alienTracker.begin(screenBox);
		updateList(alienTracker.getOnScreen(Alien.DEPTH_BG_SCENARY));
		updateList(alienTracker.getOnScreen(Alien.DEPTH_LIFTS));
		updateList(alienTracker.getOnScreen(Alien.DEPTH_COLLECTABLES));
		updateList(alienTracker.getOnScreen(Alien.DEPTH_ALIENS));
		if (isPlayerPresent) {
			drawingPlayer = true;
			player.draw();
			drawingPlayer = false;
		}
		updateList(alienTracker.getOnScreen(Alien.DEPTH_FG_SCENARY));

		alienTracker.freezeAny(screenBox);

		//
		// Caveat1: only background Aliens get to move the player around.
		// Caveat2: if any Alien does move him the scrolling for this frame
		// won't know about it (because it has already happened) but you don't
		// notice that because it is not hard scrolling but soft scrolling based
		// on a SCROLLING_TABLE.
		//
		// The Amiga version had Caveat2 (even if we didn't think about it).
		// The Amiga version did not have Caveat1 because the player was beamed
		// in last of all with some Amiga hardware-sprite wizardry.
		//
		// ... well, it's either that or we separate out moving and drawing (or
		// queue the drawing) and also accept that we won't know the exact
		// placement of the screen until quite late (which makes pixel-perfect
		// Alien freezing and defrosting impossible). That's a big voyage into
		// new territory for little gain.
		//
		// For now, it'll work how it used to but, for the first time, I can say
		// "I am clear about the limits that this imposes".
		//
	}

	private void drawTeleportEffect() {
		gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xffffffff);
	}

	private void drawTheMap() {
		horizon.draw();
		scr.drawTheMap(gameMap, blockSet);
	}

	private void drawTitles(boolean textOverHole) {
		drawRecording();
		dimFade.update();
		if (textOverHole) {
			hole.update();
			statusScreen.get().update();
		}
		else {
			statusScreen.get().update();
			hole.update();
		}
		totalFade.update();
		drawHudAndBorders(true);
	}

	public void drawRecording() {
		drawTheMap();
		for (SpriteRecord sr : recording) {
			directDrawSprite(sr.c, sr.s, sr.drawInWhite, sr.opacity);
		}
	}

	private boolean pauseAntiAutofire() {
		return pauseKey.next(keyboard.isDown(Keyboard.KEY_P)).pressed();
	}

	void drawHudAndBorders(boolean supressHurryUp) {
		scr.drawBorders(gc);
		drawHud(supressHurryUp);
	}

	private void drawHud(boolean supressHurryUp) {
		int showGems = Math.max(0, gemsNeeded - gemsCollected);
		if (isExitOpen()) {
			showGems = gemsTotal - gemsCollected;
		}
		hud.update(ow.score, timeRemainingInFrames, supressHurryUp ? false : isHurryUp(), showGems, isExitOpen(),
				ow.lives);
	}

	private boolean isHurryUp() {
		return timeRemainingInFrames < 6 * Const.FPS;
	}

	private void drawHurryUp() {
		if (isHurryUp()) {
			int flashRate = Const.FPS / 2;
			if ((frameNumber % flashRate) < (flashRate / 2)) {
				statusDisplay.drawHurryUp();
			}
		}
	}

	public void setPlayerStart(Coord c) {
		configuredPlayerStart = c;
	}

	/**
	 * The best map bounds are the smallest (i.e. the most specific) bounds that
	 * the player is inside. This allows the map designer to fence of small
	 * areas in a larger map. The player can then teleport such a small area and
	 * the {@link MapBoundsAlien} will keep him from seeing the larger map.
	 */
	private void pickTheBestBounds() {
		Box bounds = gameMap.boundsInPixels();
		long bestArea = Long.MAX_VALUE;
		for (MapBoundsAlien a : mbas) {
			Box box = a.bounds.copy();
			box.snapOutTo(Const.BLOCK_SIZE);
			// what is the smallest one that has the player in it?
			if (box.inside(player.readOnlyPlayerPosition()) && box.area() < bestArea) {
				bounds = box;
				bestArea = box.area();
			}
		}
		// that is the one for us!
		System.out.println("Map bounds: " + bounds);
		scr.setMapBoundsInPixels(bounds, bounds);
	}

	private Coord getPlayerCentreOnScreen() {
		return getPlayerCentre().sub2(scr.position());
	}

	public Coord getPlayerCentre() {
		return getPlayerPosition().copyAndAdd(0, (ttSprite.h / 2) - ttSprite.handleY);
	}

	private void captureRecording() {
		record = true;
		updateTheAliens();
		record = false;
	}

	void clearRecording() {
		recording.clear();
	}

	static private void whatAnimsDoTheyNeed(List<Alien> aliens, Set<String> animsNeeded) {
		for (Alien alien : aliens) {
			String s = alien.alienInfo.animsName();
			if (s != null) {
				animsNeeded.add(s);
			}
		}
	}

	@Override
	public void teleportTo(Coord destination) {
		if (teleportLatch.can(frameNumber)) {
			// do it
			playSoundEffect("teleport");
			teleportTimer = TELEPORT_TIME;
			teleportDestination = destination.copy();
		}
	}

	@Override
	public void playSoundEffect(String name) {
		ah.playEffect(name);
	}

	@Override
	public void applyMapEdits(Coord c, int[][] mapEdits) {
		c = c.asr2(Const.BLOCK_SHIFT);
		for (int[] line : mapEdits) {
			for (int block : line) {
				gameMap.setBlock(c, block);
				c.x++;
			}
			c.x -= line.length;
			c.y++;
		}
	}

	@Override
	public void drawDebugText(Coord c, String text) {
		Coord a = c.sub2(scr.position());
		int w = fonts.debugFont.charWidth() * text.length();
		int h = fonts.debugFont.charHeight();
		gc.fillRectangle(a.x, a.y, w, h, 0xff000000);
		fonts.debugFont.draw(a.x, a.y, 0xff00ff00, 0, text);
	}

	@Override
	public void awardExtraTime(int seconds) {
		timeRemainingInFrames /= Const.FPS;
		timeRemainingInFrames = Math.min(timeRemainingInFrames + seconds, 99);
		timeRemainingInFrames *= Const.FPS;
		timeRemainingInFrames += Const.FPS - 1;
	}

	@Override
	public void awardExtraLife() {
		if (ow.lives != 9) {
			ow.lives++;
		}
	}

	@Override
	public boolean isOffTheBottom(Coord c) {
		// *2 to be generous
		int offY = scr.position().y + gc.screenHeight() * 2;
		return c.y > offY;
	}

	private boolean isLevelCompleted() {
		return levelCompleted;
	}

	@Override
	public void levelCompleted(Coord exit) {
		if (!isLevelCompleted()) {
			levelCompleted = true;
			if (exit != null) {
				whereWeExitedTheLevel = exit.copy();
			}
			if (mode.delayedSuccess()) {
				delayedFinish.set(40);
			}
			isPlayerPresent = !mode.hasExit();
		}
	}

	@Override
	public boolean showText() {
		return !record;
	}

	// ---------------------------------------------------------------------------
	// DRAWING A FRAME: BEGIN AND END
	//

	private void begin() {
		// the main game doesn't use key events so
		// this is mostly just to drain them
		// i.e. to stop them piling up
		// (in a demo they're left for whoever is running it: name entry)
		KeyEvent keyEvent = isDemo() ? null : keyboard.nextEvent();

		if (ow.devMode) {
			if (keyEvent != null && keyEvent.keyCode == Keyboard.KEY_N && !isDemo()) {
				// finish the level (cheat_anylev in the original: done_level,
				// so the usual summary and time bonus follow)
				levelCompleted(null);
			}
			if (keyboard.isDown(Keyboard.KEY_ESCAPE)) {
				if (!configuredCalledFromMapper) {
					// called from OuterWorld
					ow.launchMapper(scr.position());
				}
				exit(Outcome.TO_MAPPER);
			}
			if (keyboard.isDown(Keyboard.KEY_D)) {
				timeRemainingInFrames = 0;
			}
		}

		firePressed |= Math2.maskTest(joystick.get(), Joystick.FIRE);

		// (before beginDrawing: we mustn't leave a frame half done)
		if (isDemo()) {
			boolean fire = Math2.maskTest(joystick.get(), Joystick.FIRE);
			if (!fire) demoFireWasUp = true;
			else if (demoFireWasUp && demoInterruptible.getAsBoolean()) endDemo(Outcome.DEMO_INTERRUPTED);
		}

		gc.beginDrawing();
	}

	private void end() {
		boolean keepGoing = demoDirector == null || demoDirector.frame();
		gc.endDrawing();
		if (!keepGoing) endDemo(Outcome.DEMO_OVER);
	}

	// ---------------------------------------------------------------------------
	// PRINCIPAL METHODS

	void maybePause() {
		if (pauseAntiAutofire()) {
			captureRecording();
			while (!pauseAntiAutofire()) {
				begin();
				drawRecording();
				if (isExitOpen()) statusDisplay.drawExitOpen();
				hole.draw();
				statusDisplay.drawPaused();
				drawHudAndBorders(false);
				end();
			}
			clearRecording();
		}

	}

	public void create() {
		hole = new Aperture(gc);
		dimFade = new Fade(gc, 0x50, 0.25f);
		totalFade = new Fade(gc, 0xff, 1f);

		// int a = 1;
		// while (a == 1) {

		System.out.println("Loading level " + ow.levelNumber);

		// pl.saveNew();
		// levelNumber++;
		// }

		alienTracker = new GameAlienTracker();

		PersistedLevel pl = new PersistedLevel(ow.levelNumber, configuredMapText);
		levelInfo = pl.getLevelInfo();
		worldName = levelInfo.worldName;

		alienInfoMap = new AlienInfoMap(worldName, this);
		AlienFactory af = new AlienFactory(alienInfoMap);
		List<Alien> aliens = pl.getAliens(af);

		// load the map
		gameMap = pl.getMap();

		// pad it top and bottom to avoid the player jumping or falling
		// and reading outside of the array
		// (this "sentinel" padding means we don't have to have
		// code for constantly checking so is a performance win)
		Box b = gameMap.boundsInBlocks().copy();
		b.top -= 8;
		lowerEdge = Const.BLOCK_SIZE * (b.bottom + 3);
		b.bottom += 8;
		gameMap = new GameMap(b, gameMap);

		pl = null;

		Coord playerStart = null;
		boolean playerFacesLeft = false;
		if (configuredPlayerStart == null) {
			PlayerAlien palien = ListUtil.findOne(PlayerAlien.class, aliens);
			if (palien != null) {
				playerStart = palien.c;
				playerFacesLeft = palien.goLeft;
			}
			else {
				throw new RuntimeException("Need a PlayerAlien to establish player's starting position!");
			}
		}
		else {
			playerStart = configuredPlayerStart;
		}

		if (!configuredCalledFromMapper) {
			// work out what Anims we need
			TreeSet<String> animsNeeded = new TreeSet<String>();
			whatAnimsDoTheyNeed(aliens, animsNeeded);
			animsNeeded.add("0tt");
			animsNeeded.add("0life");
			animsNeeded.add("0gameover");
			alienInfoMap.collectPreloadNames(animsNeeded);

			// unload what we no longer need
			// load what we do need
			animsPool.unloadReload(animsNeeded);
		}

		// (blocks of ice each have a gem inside)
		gemsTotal = ListUtil.count(GemAlien.class, aliens) + ListUtil.count(IceGemAlien.class, aliens);
		gemsNeeded = levelInfo.gemsNeeded;
		gemsCollected = 0;

		mbas = ListUtil.findMany(MapBoundsAlien.class, aliens);

		// connect the anims to the aliens
		// and load the aliens into the world
		for (Alien alien : aliens) {
			alien.connect(animsPool);
			load(alien);
		}

		horizon = ow.getHorizon(levelInfo.horizon);

		blockSet = ow.loadBlockSet(new BlockSet.Config(worldName, configuredSeeMasks, configuredSeeHidden));

		player = new Player(this, animsPool.expect("0tt"), playerStart, playerFacesLeft, lowerEdge);

		pickTheBestBounds();

		player.move(parsedJoystick);
		scr.snapTo(player.readOnlyPlayerPosition());

		blockSet.expandMap(gameMap);

		timeRemainingInFrames = levelInfo.timeGiven * Const.FPS + Const.FPS - 1;

		assert hud == null;

		Anims lifeAnims = animsPool.expect("0life");
		hud = new HeadUpDisplay(gc, fonts.font, lifeAnims.find(0).firstSprite());
		statusDisplay = new StatusDisplay(gc, fonts.font);

		createGameMode();
	}

	/**
	 * The start of a level, as init_game in s195: (from a black screen) the
	 * world's logo if it's a new world, the level drawn and the circle opening
	 * on it with everything frozen, then (in a real game) what the level is
	 * and a wait for fire. Then the music.
	 */
	private void performStart() {
		assert mode != null;
		ah.stopMusic();
		if (configuredWorldLogo && !worldName.equals(ow.worldLogoShown)) {
			showWorldLogo();
			ow.worldLogoShown = worldName;
		}

		if (isDemo()) {
			ah.loadMusic(1, configuredDemoMusic != null ? configuredDemoMusic : worldName);
		}
		else {
			ah.loadMusic(3, "gameover");
			ah.loadMusic(2, "levelcomplete");
			ah.loadMusic(1, worldName);
			ah.loadMusic(0, "levelbegin");
			ah.startMusic(0);
		}

		captureRecording();
		openCircle();
		if (!isDemo()) explainLevel();
		clearRecording();

		ah.startMusic(1);
	}

	/**
	 * show_world_logo: on black, fade the logo in, show it for 3 seconds (or
	 * until fire) and fade it out again.
	 */
	private void showWorldLogo() {
		String name = "0logo" + worldName;
		if (!TTResource.animExists(name)) return;
		ah.loadMusic(5, "startworld");
		ah.startMusic(5);
		final Sprite logo = loadPicture(name);
		try {
			final int cx = gc.screenWidth() / 2;
			final int cy = gc.screenHeight() / 2;
			Runnable draw = () -> {
				gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xff000000);
				logo.drawByHandle(cx, cy, false);
			};
			int f = 0;
			for (; f < FADE_FRAMES; f++) {
				final int dark = FADE_FRAMES - 1 - f;
				frame(() -> {
					draw.run();
					darken(dark);
				});
			}
			// (logo_timer: 3 seconds from when it went up)
			for (; f < 3 * Const.FPS && !fireHeld(); f++) {
				frame(draw);
			}
			fadeToBlack(draw);
		}
		finally {
			logo.dispose();
		}
	}

	/** A whole picture as a sprite with its handle in the middle. */
	private Sprite loadPicture(String name) {
		com.nney.tt.gfx.SimpleImage si = new com.nney.tt.gfx.SimpleImage(
				com.nney.utils.OpenableTools.mustLoad(TTResource.bareSprite(name)));
		com.nney.tt.gfx.Bounds b = si.bounds();
		return new Sprite(gc, si.view(b), si.width() / 2 - b.left, si.height() / 2 - b.top, false);
	}

	/**
	 * cartoon_circle: opens from radius 10, 2 pixels a frame, centred 16 pixels
	 * above Thomas's feet, until it's past the furthest corner of the screen.
	 * Nothing else moves.
	 */
	private void openCircle() {
		final Coord p = player.readOnlyPlayerPosition().sub2(scr.position());
		p.y -= 16;
		int w = gc.screenWidth();
		int h = gc.screenHeight();
		int dx = (p.x > w / 2 ? 0 : w) - p.x;
		int dy = (p.y > h / 2 ? 0 : h) - p.y;
		int maxRadius = (int) Math.ceil(Math.sqrt((double) dx * dx + (double) dy * dy)) + 5;
		for (int r = 10; r < maxRadius; r += 2) {
			final int radius = r;
			frame(() -> {
				drawFrozen(true);
				gc.aperture(radius, p.x, p.y, 0xff000000);
				drawHudAndBorders(true);
			});
		}
	}

	/** explain_level: what this level is, until fire is pressed. */
	private void explainLevel() {
		createStatusScreen(mode.introText());
		Runnable draw = this::drawFrozenText;
		// a press left over from before doesn't count
		while (fireHeld()) {
			frame(draw);
		}
		waitForFire(-1, draw);
	}

	public void createGameMode() {
		final int levelNum = ow.levelNumber + 1;
		final String levelTitle = levelInfo.title;

		if (levelTitle.equals("challenge:race")) {
			final String text = Messages.raceChallenge(levelNum, levelInfo.timeGiven);
			mode = new Mode() {
				@Override
				public boolean delayedSuccess() {
					return true;
				}

				@Override
				public String successMessage() {
					return Messages.levelComplete(ow.levelNumber + 1, levelInfo.title, gemsCollected, gemsTotal
							- gemsCollected, timeRemainingInFrames / Const.FPS, player.gotStar(), false);
				}

				@Override
				public String failMessage() {
					return Messages.challengeFailed(ow.levelNumber + 1);
				};

				@Override
				public void onTimeOut() {
					performLevelFailure();
				}

				@Override
				public String introText() {
					return text;
				}

				@Override
				public boolean hasExit() {
					return false;
				}
			};
		}
		else if ("challenge:letters".equals(levelInfo.mode)) {
			final String text = Messages.finalChallenge(levelNum);
			mode = new Mode() {
				@Override
				public String successMessage() {
					return Messages.challengeCompleteExtraLife(ow.levelNumber + 1, timeRemainingInFrames / Const.FPS);
				}

				@Override
				public String failMessage() {
					return Messages.challengeFailedNoExtraLife(ow.levelNumber + 1);
				}

				@Override
				public void onTimeOut() {
					performLevelFailure();
				}

				@Override
				public String introText() {
					return text;
				}

				@Override
				public boolean hasExit() {
					return false;
				}
			};
		}
		else if (levelTitle.equals(":fruit") || "fruit".equals(levelInfo.mode)) {
			final String text = Messages.fruit(levelNum, levelInfo.timeGiven);
			mode = new Mode() {
				@Override
				public String successMessage() {
					return Messages.fruitComplete(ow.levelNumber + 1);
				}

				@Override
				public boolean hasExit() {
					return false;
				}

				@Override
				public void onTimeOut() {
					levelCompleted(null);
				}

				@Override
				public String introText() {
					return text;
				}

				@Override
				public boolean pauseGameDuringOutro() {
					return true;
				};
			};
		}
		else {
			normalLevel = true;
			final String text = Messages.levelStart(levelNum, levelTitle, levelInfo.gemsNeeded, gemsTotal,
					levelInfo.timeGiven);
			mode = new Mode() {
				@Override
				public String successMessage() {
					return Messages.levelComplete(ow.levelNumber + 1, levelInfo.title, gemsCollected, gemsTotal
							- gemsCollected, timeRemainingInFrames / Const.FPS, player.gotStar(), perfectLevel);
				}

				@Override
				public void onTimeOut() {
					timeUp();
				}

				@Override
				public String introText() {
					return text;
				}
			};
		}
	}

	private void oneMainFrame() {
		checkTeleportation();

		maybePause();

		if (configuredPlayerStart == null && !isLevelCompleted()) {
			int timeDec = player.isStunned() ? 3 : 1;
			timeRemainingInFrames = Math.max(timeRemainingInFrames - timeDec, 0);
		}

		if (player.isLostOffTheBottom()) {
			offTheBottom();
		}

		if (timeRemainingInFrames == 0) {
			mode.onTimeOut();
		}

		//
		// MODE MAIN
		//
		begin();

		int j;
		if (isDemo()) j = demoJoystick.get();
		else if (scriptReader != null) j = scriptReader.get();
		else j = joystick.get();
		if (scriptWriter != null) scriptWriter.put(j);
		mainActions(j);

		dimFade.update();

		if (isExitOpen()) statusDisplay.drawExitOpen();
		drawHurryUp();

		hole.update();
		drawHudAndBorders(false);

		end();

		if (isLevelCompleted() && isDemo()) endDemo(Outcome.DEMO_OVER);

		if (isLevelCompleted()) {
			if (!delayedFinish.testAndRun()) {
				if (!didScroll || mode.pauseGameDuringOutro()) {
					performLevelComplete();
				}
			}
		}
	}

	/**
	 * A challenge's time ran out (challenge_fail in s195): Thomas goes, the
	 * message, and on to the next level.
	 */
	private void performLevelFailure() {
		if (isDemo()) endDemo(Outcome.DEMO_OVER);
		collisionDetection = false;
		isPlayerPresent = false;
		captureRecording();
		createStatusScreen(mode.failMessage());
		Runnable draw = this::drawFrozenText;
		waitForFire(WAIT4FIRE, draw);
		fadeToBlack(draw);
		ow.levelNumber++;
		ow.starCollected = false;
		exit(Outcome.COMPLETED);
	}

	/**
	 * Out of time on an ordinary level (flash_timeup in s195): "time up"
	 * flashes with everything frozen, a life goes, the clock is refilled and
	 * play carries on.
	 */
	private void timeUp() {
		if (isDemo()) endDemo(Outcome.DEMO_OVER);
		if (ow.lives <= 1) performGameOver();
		captureRecording();
		for (int phase = 0; phase < 5; phase++) {
			final boolean show = phase % 2 == 1;
			for (int f = 0; f < 13; f++) {
				frame(() -> {
					drawFrozen(true);
					if (show) statusDisplay.drawTimeUp();
					drawHudAndBorders(true);
				});
			}
		}
		clearRecording();
		ow.lives--;
		lifeLostHere = true;
		timeRemainingInFrames = levelInfo.timeGiven * Const.FPS + Const.FPS - 1;
	}

	/** Fell off the bottom: a life goes, fade to black and start the level again. */
	private void offTheBottom() {
		if (isDemo()) endDemo(Outcome.DEMO_OVER);
		if (ow.lives <= 1) performGameOver();
		ow.lives--;
		ah.stopMusic();
		captureRecording();
		fadeToBlack(() -> {
			drawFrozen(true);
			drawHudAndBorders(true);
		});
		exit(Outcome.LIFE_LOST);
	}

	/**
	 * tell_gameover: "game" slides in from the left and "over" from the right,
	 * a wait for fire, and they carry on across and off.
	 */
	private void performGameOver() {
		collisionDetection = false;
		ow.lives = Math.max(0, ow.lives - 1);
		ah.startMusic(3);
		isPlayerPresent = false;
		captureRecording();
		Anims ago = animsPool.expect("0gameover");
		final Sprite game = ago.find("game").firstSprite();
		final Sprite over = ago.find("over").firstSprite();
		final int mx = gc.screenWidth() / 2;
		final int my = gc.screenHeight() / 2;
		final int[] d = new int[1];
		Runnable draw = () -> {
			drawFrozen(true);
			game.drawByHandle(mx - d[0], my - 14, false);
			over.drawByHandle(mx + d[0], my + 13, false);
			drawHudAndBorders(true);
		};
		IntConsumer at = x -> {
			d[0] = x;
			frame(draw);
		};
		for (int x = 208; x >= 0; x -= 8) {
			at.accept(x);
		}
		waitForFire(WAIT4FIRE, draw);
		for (int x = -24; x >= -216; x -= 16) {
			at.accept(x);
		}
		fadeToBlack(() -> {
			drawFrozen(true);
			drawHudAndBorders(true);
		});
		exit(Outcome.GAME_OVER);
	}

	// gc.fillRectangle(t.x, 0, 1, 1000, 0xffff00ff);
	// gc.fillRectangle(0, t.y, 1000, 1, 0xffff00ff);

	private void mainActions(int joystickPosition) {
		frameNumber++;
		currentJoystick = joystickPosition;

		moveLifts();

		if (isPlayerPresent) {
			parsedJoystick.set(joystickPosition);
			player.move(parsedJoystick);
		}

		if (CTC_MEASURE_JUMP_HEIGHT) {
			smallestY = Math.min(smallestY, player.readOnlyPlayerPosition().y);
			System.out.println(String.format("Player: %s (smallesty:%s height:%s)", player.readOnlyPlayerPosition(),
					smallestY, player.readOnlyPlayerPosition().y - smallestY));
			if (keyboard.isDown(Keyboard.KEY_R)) {
				smallestY = Integer.MAX_VALUE;
			}
		}

		// JUMP HEIGHT: 66 .. 68 with the bug (of course)

		scrollTheScreen();
		drawTheMap();
		updateTheAliens();
	}

	private void moveLifts() {
		for (Alien a : alienTracker.getOnScreen(Alien.DEPTH_LIFTS)) {
			LiftAlien l = (LiftAlien) a;
			l.move();
		}
	}

	private void scrollTheScreen() {
		Coord orig = scr.position().copy();
		if (isPlayerPresent) {
			if (CTC_HARD_SCROLLING) {
				scr.snapTo(player.readOnlyPlayerPosition());
			}
			else {
				scr.scrollTo(player.readOnlyPlayerPosition());
			}
		}
		didScroll = !orig.equals(scr.position());
	}

	private void checkTeleportation() {
		while (teleportTimer != 0) {
			begin();
			teleportTimer--;
			drawTeleportEffect();
			drawHudAndBorders(false);
			if (teleportTimer == TELEPORT_TIME / 2) {
				player.teleportTo(teleportDestination);
				pickTheBestBounds();
				scr.snapTo(player.readOnlyPlayerPosition());
			}
			end();
		}
	}

	private void performMain() {
		for (;;) {
			oneMainFrame();
		}
	}

	/**
	 * The level's done (explain_complete in s195): Thomas goes, the jingle, the
	 * summary (held for 3 seconds unless fire is down), the time left counted
	 * into the score a second at a time, a wait for fire, and a fade to black.
	 * After the last level: the ending's pages instead of the summary.
	 */
	private void performLevelComplete() {
		collisionDetection = false;
		ah.startMusic(2);
		perfectLevel = normalLevel && gemsCollected >= gemsTotal && !lifeLostHere;
		if (perfectLevel) awardScore(PERFECT_BONUS, null);
		ow.levelsCompleted++;
		ow.gemsCollectedTotal += gemsCollected;

		isPlayerPresent = false;
		captureRecording();
		Runnable draw = this::drawFrozenText;
		if (configuredEnding != null) {
			for (String page : configuredEnding.get()) {
				createStatusScreen(page);
				// (showmsgD: up to 12 seconds a page)
				waitForFire(12 * Const.FPS, draw);
			}
		}
		else {
			createStatusScreen(mode.successMessage());
			boolean fire = false;
			for (int f = 0; f < 150 && !fire; f++) {
				frame(draw);
				fire = fireHeld();
			}
			int seconds = timeRemainingInFrames / Const.FPS;
			while (!fire && seconds > 0) {
				seconds--;
				awardScore(10, null);
				playSoundEffect("tink");
				timeRemainingInFrames = seconds * Const.FPS;
				frame(draw);
				fire = fireHeld();
			}
			awardScore(seconds * 10, null);
			timeRemainingInFrames = 0;
			waitForFire(WAIT4FIRE, draw);
		}
		fadeToBlack(draw);

		ow.levelNumber++;
		ow.starCollected = player.gotStar();
		exit(Outcome.COMPLETED);
	}

	/** A demo has finished (or been stopped): fade it to black. */
	private void endDemo(Outcome o) {
		captureRecording();
		fadeToBlack(() -> {
			drawFrozen(true);
			drawHudAndBorders(true);
		});
		exit(o);
	}

	// ---------------------------------------------------------------------------
	// FRAMES OF THE SEQUENCES (nothing moves; the screen is the "recording")

	/** One frame of a sequence. */
	private void frame(Runnable draw) {
		gc.beginDrawing();
		draw.run();
		gc.endDrawing();
	}

	private boolean fireHeld() {
		return Math2.maskTest(joystick.get(), Joystick.FIRE);
	}

	/**
	 * wait4fire in s195: until fire is down (or the time is up; negative for
	 * no limit), then two frames, then until it's let go.
	 */
	private void waitForFire(int frames, Runnable draw) {
		for (int f = 0; (frames < 0 || f < frames) && !fireHeld(); f++) {
			frame(draw);
		}
		if (fireHeld()) {
			frame(draw);
			frame(draw);
			while (fireHeld()) {
				frame(draw);
			}
		}
	}

	/** fade_out: whatever draw draws, darker each frame until it's black. */
	private void fadeToBlack(Runnable draw) {
		for (int f = 0; f < FADE_FRAMES; f++) {
			final int dark = f + 1;
			frame(() -> {
				draw.run();
				darken(dark);
			});
		}
	}

	/** Darken the screen by steps sixteenths. */
	private void darken(int steps) {
		if (steps <= 0) return;
		int a = Math.min(255, 256 * steps / FADE_FRAMES);
		gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), a << 24);
	}

	/** The frozen screen: the map and what was drawn on it (perhaps not the aliens). */
	private void drawFrozen(boolean showAliens) {
		drawTheMap();
		for (SpriteRecord sr : recording) {
			if (sr.isPlayer || (showAliens && !aliensHidden)) {
				directDrawSprite(sr.c, sr.s, sr.drawInWhite, sr.opacity);
			}
		}
	}

	/** A text screen over the frozen screen: it takes the aliens' place. */
	private void drawFrozenText() {
		drawFrozen(false);
		statusScreen.get().update();
		drawHudAndBorders(true);
	}

	// ---------------------------------------------------------------------------
	// ENTRY POINTS

	public void configurePlayerStart(Coord c) {
		configuredPlayerStart = c;
	}

	public void configureMapText(String s) {
		configuredMapText = s;
	}

	public void configurePerformIntro(boolean b) {
		configuredPerformIntro = b;
	}

	public void configureScriptRecording(String filename) {
		configuredScriptDestination = filename;
		scriptWriter = new ScriptWriter();
	}

	public void configureScriptPlayback(String filename) {
		scriptReader = new ScriptReader(TTResource.asText(TTResource.script(filename)));
	}

	public void testLevelFromMapper() {
		configuredCalledFromMapper = true;
		playLevel();
	}

	public void configureSeeHidden(boolean b) {
		configuredSeeHidden = b;
	}

	public void configureSeeMasks(boolean b) {
		configuredSeeMasks = b;
	}

	/**
	 * Play this level until something ends it.
	 * 
	 * @return What ended it.
	 */
	public Outcome playLevel() {
		try {
			create();
			if (configuredPerformIntro || isDemo()) performStart();
			performMain();
		}
		catch (ExitException ex) {
		}
		finally {
			if (cr != null) cr.close();
		}
		if (scriptWriter != null) {
			TTResource.saveScript(configuredScriptDestination, scriptWriter.save());
		}
		dispose();
		return outcome;
	}

	/**
	 * Show the world's logo first if it's not the one shown last (the default
	 * in a game; see {@link OuterWorld#worldLogoShown}).
	 */
	public void configureWorldLogo(boolean b) {
		configuredWorldLogo = b;
	}

	/** In a demo: the music to play (rather than the world's). */
	public void configureDemoMusic(String name) {
		configuredDemoMusic = name;
	}

	/** In a demo: may fire stop it just now? (Not while a name is entered.) */
	public void configureDemoInterruptible(BooleanSupplier b) {
		demoInterruptible = b;
	}

	/** The last level: when it's done, these pages instead of the summary. */
	public void configureEnding(Supplier<String[]> pages) {
		configuredEnding = pages;
	}

	/**
	 * Hide the aliens (not Thomas), as the original's text screens did: they
	 * were drawn in the aliens' bitplanes.
	 */
	public void setAliensHidden(boolean b) {
		aliensHidden = b;
	}


	// ---------------------------------------------------------------------------
	// (RE)LOAD AND FREE

	private void createStatusScreen(String text) {
		statusScreen.dispose();
		StatusScreen ss = new StatusScreen(gc, fonts.font);
		OsdParser osdParser = new OsdParser(ss);
		osdParser.parse(text);
		ss.done();
		statusScreen.set(ss);
	}

	@Override
	public void dispose() {
		// this presupposes create() ran successfully
		if (!isDemo()) ah.stopMusic();
		statusScreen.dispose();
		hud.dispose();
		statusDisplay.dispose();
	}

	public Coord getScreenPosition() {
		return scr.position();
	}
}

// 64: worm - forget it

// new life every 50,000 points
// 10,000 points for perfect level
// 10 points for every spare second
//
// 500 for the big gem
// 2500 for the huge gem
// 50, 100 for the yellow and purple gem

