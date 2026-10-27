package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

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

		SpriteRecord(Coord c, Sprite s, boolean drawInWhite) {
			this.c = c.copy();
			this.s = s;
			this.drawInWhite = drawInWhite;
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
		if (record) {
			recording.add(new SpriteRecord(c, s, drawWhite));
		}
		else {
			directDrawSprite(c, s, drawWhite);
		}
	}

	private void directDrawSprite(Coord c, final Sprite s, boolean drawWhite) {
		Coord screen = scr.position();
		final int x = c.x - screen.x;
		final int y = c.y - screen.y;
		s.drawByHandle(x, y, drawWhite);
	}

	@Override
	public void registerPlayerSpriteForAlienColisions(Coord c, Sprite s) {
		playerSpriteTopLeft = c.copy();
		playerSpriteTopLeft.x -= s.handleX;
		playerSpriteTopLeft.y -= s.handleY;
		ttSprite = s;
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
			player.draw();
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
			directDrawSprite(sr.c, sr.s, sr.drawInWhite);
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
		KeyEvent keyEvent = keyboard.nextEvent();

		if (ow.devMode) {
			if (keyEvent != null && keyEvent.keyCode == Keyboard.KEY_N && !isDemo()) {
				// skip to the next level (cheat_anylev in the original)
				ow.levelNumber++;
				ow.starCollected = false;
				exit(Outcome.COMPLETED);
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
			else if (demoFireWasUp) exit(Outcome.DEMO_INTERRUPTED);
		}

		gc.beginDrawing();
	}

	private void end() {
		boolean keepGoing = demoDirector == null || demoDirector.frame();
		gc.endDrawing();
		if (!keepGoing) exit(Outcome.DEMO_OVER);
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

	private void performIntro() {
		assert mode != null;
		captureRecording();

		hole.setCentre(getPlayerCentreOnScreen());
		hole.current(Curtain.CLOSED);
		hole.target(Curtain.OPEN);

		dimFade.current(Curtain.CLOSED);
		dimFade.target(Curtain.CLOSED);

		// totalFade.current(Curtain.OPEN);
		// totalFade.target(Curtain.OPEN);

		ah.loadMusic(3, "gameover");
		ah.loadMusic(2, "levelcomplete");
		ah.loadMusic(1, worldName);
		ah.loadMusic(0, "levelbegin");
		ah.startMusic(0);

		createStatusScreen(mode.introText());

		//
		// MODE START
		//
		while (!firePressed) {
			begin();
			drawTitles(false);
			end();
		}

		dimFade.target(Curtain.OPEN);
		ah.startMusic(1);

		clearRecording();
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
							- gemsCollected, timeRemainingInFrames / Const.FPS, player.gotStar());
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
			final String text = Messages.levelStart(levelNum, levelTitle, levelInfo.gemsNeeded, gemsTotal,
					levelInfo.timeGiven);
			mode = new Mode() {
				@Override
				public String successMessage() {
					return Messages.levelComplete(ow.levelNumber + 1, levelInfo.title, gemsCollected, gemsTotal
							- gemsCollected, timeRemainingInFrames / Const.FPS, player.gotStar());
				}

				@Override
				public void onTimeOut() {
					performLevelFailure();
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
			performLevelFailure();
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

		if (isLevelCompleted() && isDemo()) exit(Outcome.DEMO_OVER);

		if (isLevelCompleted()) {
			if (!delayedFinish.testAndRun()) {
				if (!didScroll || mode.pauseGameDuringOutro()) {
					createStatusScreen(mode.successMessage());

					Coord closeAround = whereWeExitedTheLevel;
					if (closeAround == null) closeAround = getPlayerCentre();
					closeAround.sub(scr.position());
					hole.setCentre(closeAround);
					hole.target(Curtain.CLOSED);
					hole.setRate(4);

					// happy outro
					performOutro();
				}
			}
		}
	}

	private void performLevelFailure() {
		if (isDemo()) exit(Outcome.DEMO_OVER);

		collisionDetection = false;

		if (!player.isLostOffTheBottom()) {
			player.kill();
			// we need to keep waiting until
			// he is on his arse and the screen has stopped scrolling
			do {
				if (player.isLostOffTheBottom()) break;
				begin();
				mainActions(0);
				drawHudAndBorders(false);
				end();
			} while (!player.onArse() || didScroll);
		}

		// the magic 2 and -6 compensate for the player sitting down
		final Coord t = getPlayerCentreOnScreen().copyAndAdd(2, -6);
		hole.setCentre(t);
		hole.current(Curtain.OPEN);
		hole.target(Curtain.CLOSED);
		hole.setRate(3);

		String failMessage = mode.failMessage();
		if (failMessage != null) {
			createStatusScreen(failMessage);
			// sad outro
			performOutro();
		}
		else {
			performLifeLost(t);
		}
	}

	public void performLifeLost(final Coord t) {
		boolean gameOver = ow.lives <= 1;
		LifeLostDevice lifeLostDevice;

		boolean start = false;
		if (gameOver) {
			lifeLostDevice = new GameOverDisplay(animsPool, gc);
			ah.startMusic(3);
			start = true;
		}
		else {
			lifeLostDevice = new LifeLostDevice() {
				@Override
				public void update() {
					statusDisplay.drawLifeLost(t.copyAndAdd(0, 28));
				}

				@Override
				public boolean isDone() {
					return true;
				}
			};
		}

		SlowBoolean decLives = new SlowBoolean(true);
		do {
			begin();
			mainActions(0);
			hole.update();
			int p = hole.current();
			if (p > 60) start = true;
			if (start) {
				if (decLives.set(false)) {
					ow.lives--;
				}
				lifeLostDevice.update();
			}
			drawHudAndBorders(false);
			end();
		} while (!lifeLostDevice.isDone() || !hole.isDone());

		Fade fadeOut = new Fade(gc, 0xff, 0.30f);
		fadeOut.target(Curtain.CLOSED);
		do {
			begin();
			lifeLostDevice.update();
			fadeOut.update();
			drawHudAndBorders(false);
			end();
		} while (!fadeOut.isDone());

		exit(gameOver ? Outcome.GAME_OVER : Outcome.LIFE_LOST);
	}

	// gc.fillRectangle(t.x, 0, 1, 1000, 0xffff00ff);
	// gc.fillRectangle(0, t.y, 1000, 1, 0xffff00ff);

	private void mainActions(int joystickPosition) {
		frameNumber++;

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

	private void performOutro() {
		collisionDetection = false;

		dimFade.target(Curtain.CLOSED);

		cr = new Coroutine("timeBonus", co -> {
			// wait around a bit
			co.pause(60);

			//
			// turn time into score
			//
			int fastScore = 0;
			while (timeRemainingInFrames != 0) {
				if (firePressed) {
					fastScore += 10;
				}
				else {
					awardScore(10, null);
					playSoundEffect("tink");
					co.pause(4);
				}
				timeRemainingInFrames = Math.max(0, timeRemainingInFrames - Const.FPS);
			}
			awardScore(fastScore, null);

			// a pause so you get to look at it
			co.pause(25);

			//
			// wait for fire
			//
			while (!firePressed) {
				co.pause();
			}

			//
			// fade to black
			//
			totalFade.target(Curtain.CLOSED);
			while (!totalFade.isDone()) {
				co.pause();
			}
		});

		// captureRecording();
		// while (!pauseAntiAutofire()) {
		// begin();
		// drawTheMap();
		// for (SpriteRecord sr : recording) {
		// directDrawSprite(sr.c, sr.s, sr.drawInWhite);
		// }
		// if (isExitOpen()) statusDisplay.drawExitOpen();
		// hole.draw();
		// statusDisplay.drawPaused();
		// drawHudAndBorders(false);
		// end();
		// }

		ah.startMusic(2);

		firePressed = false;

		if (mode.pauseGameDuringOutro()) {
			captureRecording();
		}
		boolean done = false;
		while (!done) {
			begin();
			if (mode.pauseGameDuringOutro()) {
				drawRecording();
			}
			else {
				mainActions(0);
			}
			hole.update();
			statusScreen.get().update();
			totalFade.update();
			drawHudAndBorders(true);

			if (!cr.step()) done = true;
			end();
		}
		cr.close();
		ow.levelNumber++;
		ow.starCollected = player.gotStar();
		ow.levelsCompleted++;
		ow.gemsCollectedTotal += gemsCollected;
		exit(Outcome.COMPLETED);
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
			if (configuredPerformIntro) performIntro();
			else if (isDemo()) prepareDemoStart();
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

	private void prepareDemoStart() {
		// iris in on the player, as at the start of a normal level
		hole.setCentre(getPlayerCentreOnScreen());
		hole.current(Curtain.CLOSED);
		hole.target(Curtain.OPEN);
		dimFade.current(Curtain.OPEN);
		dimFade.target(Curtain.OPEN);
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

