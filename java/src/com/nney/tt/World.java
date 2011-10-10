package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import com.nney.coroutines.CoTerminated;
import com.nney.coroutines.Coroutine;
import com.nney.tt.BlockSet.Config;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienWithLocation;
import com.nney.tt.aliens.FallingAlien;
import com.nney.tt.aliens.GemAlien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.MapBoundsAlien;
import com.nney.tt.aliens.PlayerAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.Mapper;
import com.nney.tt.mapper.NearestAlienFinder;
import com.nney.tt.osd.HeadUpDisplay;
import com.nney.tt.osd.OsdParser;
import com.nney.tt.osd.StatusDisplay;
import com.nney.tt.osd.StatusScreen;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.AudioHub;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsDefPool;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.LineInfo;
import com.nney.tt.sprites.Sprite;

public class World implements AlienServices, WorldServicesToMapper {
	public static final Box WHOLE_MAP_BOUNDS_IN_PIXELS = Box.fromTopLeftAndSize(0, 0, GameMap.MAP_WIDTH
			* Const.BLOCK_SIZE, GameMap.MAP_HEIGHT * Const.BLOCK_SIZE);

	private static final int BORDER_COLOR = 0xff000000;

	final private GraphicsContext gc;

	private final Joystick joystick;
	private final Keyboard keyboard;

	private int levelNumber = 0;
	// 8 map+code: needs lift 0
	// 9 map+code: needs lift 0
	// 10 ok
	// 11 map+code: needs lift 101
	// 12 map: secret area visible
	// 13 map|code: fall through??
	// 14 ok
	// 15 the gallery:
	// -- map: wall priority

	// TODO: secret areas should be bounded by those things

	// TODO: code ballon man
	// TODO: code lives--
	// TODO: mapper: reset on enter?

	private int score = 0;

	private int lives = 3;

	// Disposable:
	private HeadUpDisplay hud;

	private AlienInfoMap alienInfoMap;
	// Disposable:
	private AnimsPool animsPool;

	// block set
	// Disposable:
	private BlockSet blockSet;

	// Disposable:
	private Horizon horizon;

	// mapper vars
	private boolean usingMapper;

	private Mapper mapper;

	private Pointer mouse;

	private String worldName;

	private ScreenPosition scr;

	/**
	 * Compile time configuration: the screen follows the player <b>exactly</b>.
	 */
	private static final boolean CTC_HARD_SCROLLING = false;

	final private Random rnd = new Random(5);

	private Player player;

	private GameMap gameMap;

	private AlienTracker alienTracker;

	private int frameNumber;

	/**
	 * Player sprite.
	 */
	private Sprite ttSprite;

	/**
	 * Player sprite top level (i.e. incorporates handle subtraction).
	 */
	private Coord playerSpriteTopLeft;

	private int timeRemaining;

	private int gemsNeeded;

	private int gemsTotal;

	private int gemsCollected;

	enum GameMode {
		PLAYING, PAUSED, COMPLETE, START
	}

	private GameMode mode = GameMode.PLAYING;

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
	 * {@link Alien#update()}. {@link World#updateEverything()} is expected just
	 * draw the screen when the game is paused but there is no on {@link Alien}
	 * to just draw it. This is because all the update methods are modelled on
	 * their 68000 originals.
	 * 
	 * <p>
	 * Solution: we spend one frame recording where all the {@link Sprite}s are
	 * drawn then we just play it back while we're paused without any calls any
	 * methods on the {@link Alien}s.
	 * 
	 * <p>
	 * ORRR.... I was thinking about using SpriteRecords in order to have to
	 * {@link Alien#update()} the aliens according to their {@link Alien#depth}.
	 * Recording for one frame is awkward - it delays our intent by one frame
	 * ... meaning we have to track that intent and also the game world moves on
	 * by one frame. Maybe we record all the time? It need not generate garbage
	 * if done right and then Aliens could sit in a single list. That's
	 * something to consider.
	 * 
	 * 
	 * <p>
	 * This is where we store the recording.
	 */
	private final ArrayList<SpriteRecord> recording = new ArrayList<World.SpriteRecord>();

	/**
	 * Were we pressing the pause key last frame?
	 */
	private boolean wasPauseKeyPressedLastFrame;

	// ---------------------------------------------------------------------------
	private StatusDisplay statusDisplay;

	private boolean record;

	private boolean completed;

	private StatusScreen statusScreen;

	private PersistedLevel pl;

	private Aperture hole;

	private Fade dimFade;

	private Fade totalFade;

	private boolean firePressed;

	private Coroutine cr;

	private AudioHub ah;

	private Config blocksetConfig = new BlockSet.Config(false, false);
	
	private static final int TELEPORT_TIME = 50;

	private int teleportTimer;

	private final Latch teleportLatch = new Latch();

	private Coord teleportDestination;

	private Fonts fonts;

	public World(GraphicsContext gc, AudioContext ac, Joystick joystick, Keyboard keyboard, Pointer mouse) {
		this.gc = gc;
		this.ah = new AudioHub(ac);
		this.scr = new ScreenPosition(gc.screenWidth(), gc.screenHeight());
		this.joystick = joystick;
		this.keyboard = keyboard;
		this.mouse = mouse;

		this.fonts = new Fonts(gc);

		alienInfoMap = new AlienInfoMap();
		animsPool = new AnimsPool(gc, new AnimsDefPool());

		initLevel();
	}

	// ---------------------------------------------------------------------------
	// MOSTLY SERVICES FOR THE ALIEN IMPLEMENTATIONS TO CALL

	@Override
	public int randomness(int n) {
		return rnd.nextInt(n);
	}

	private int getBlock(Coord c) {
		int x = c.x / Const.BLOCK_SIZE;
		int y = c.y / Const.BLOCK_SIZE;
		return gameMap.fastGetBlock(x, y);
	}

	@Override
	public boolean inTheGround(Coord c) {
		int block = getBlock(c);
		return blockSet.maskHolder.inTheGround(block, c.x & 15, c.y & 15);
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
		return blockSet.wi.blockInformation.get(block);
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
		return gemsCollected >= gemsNeeded;
	}

	// ---------------------------------------------------------------------------
	// DRAWING

	@Override
	final public void drawSprite(Coord c, Sprite s) {
		drawSprite(c, s, false);
	}

	@Override
	final public void drawSprite(Coord c, final Sprite s, boolean drawWhite) {
		assert mode != GameMode.PAUSED;
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
		return player.c;
	}

	@Override
	public void validatePlayerPosition(Coord c) {
		scr.keepPlayerInMap(c);
	}

	@Override
	public int getFrameNumber() {
		return frameNumber;
	}

	@Override
	public boolean collideBoxWithPlayer(Box box) {
		int diffX = player.c.x;
		int diffY = player.c.y;

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
						return true;
					}
				}
			}
		}
		return false;
	}

	@Override
	public boolean collideBoxWithPlayerHandle(Box box) {
		int diffX = player.c.x;
		int diffY = player.c.y;
		if (diffX >= box.left) {
			if (diffX <= box.right) {
				if (diffY >= box.top) {
					if (diffY <= box.bottom) {
						return true;
					}
				}
			}
		}
		return false;
	}

	@Override
	public void headBounce(AlienWithLocation alien, Sprite alienSprite) {
		Coord alienPos = alien.c;
		int dy = alienPos.y - alienSprite.handleY - playerSpriteTopLeft.y;
		if (dy < ttSprite.h && dy > 0) {
			int consideredInTearaway = ttSprite.h - 1 - dy;
			if (player.isHeadBouncePossible(consideredInTearaway)) {
				int diffX = Math.abs(alienPos.x - player.c.x);
				int w = Math.abs(alienSprite.w) / 2 + 6;
				System.out.println(String.format("SpareX: %s <= %s (w=%s)", diffX, w, alienSprite.w));
				if (diffX <= w) {
					// head bounce :)
					playSoundEffect("headbounce");
					Anim frightAnim = alien.anims.mightFind("fright");
					boolean willSurvive = frightAnim == null;
					int headScore = player.headBounce(willSurvive);
					int raiseScoreNoticeBy = alienSprite.handleY + 10;
					if (willSurvive) {
						awardScore(headScore, new Coord(alienPos.x, alienPos.y - raiseScoreNoticeBy));
					}
					else {
						alien.done();
						FallingAlien fa = new FallingAlien(alien.c, headScore, raiseScoreNoticeBy, frightAnim);
						attachConnectLoad(fa);
					}
					return;
				}
				else {
					System.out.println("NoHeadBounce: diffX");
				}
			}
		}

		// no head bounce :(
		player.stun();
	}

	// TODO: unused
	@Override
	public boolean collideAlienWithPlayerBounds(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - playerSpriteTopLeft.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - playerSpriteTopLeft.y;
			return dy < ttSprite.h && dy > (-alienSprite.h);
		}
		return false;
	}

	@Override
	public boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - playerSpriteTopLeft.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - playerSpriteTopLeft.y;
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

	@Override
	public Player getThePlayer() {
		return player;
	}

	@Override
	public Joystick getStick() {
		return joystick;
	}

	@Override
	public LadderInformation getLadderInfo() {
		return blockSet.wi.ladderInformation;
	}

	@Override
	public boolean frameTest(int mask, int lessThan) {
		return (getFrameNumber() & (mask - 1)) < lessThan;
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
		score += amount;
		if (location != null) {
			attachConnectLoad(new ScoreNoticeAlien(amount, location.copy()));
		}
	}

	@Override
	public void magicDust(Coord location) {
		attachConnectLoad(new MagicDustAlien(location.copy()));
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

	@Override
	public void load(Alien alien) {
		alien.load(this);
		alienTracker.delayedAdd(alien);
	}

	// ---------------------------------------------------------------------------

	private void updateList(List<Alien> alienList, Box screenBox, boolean mapper) {
		for (Iterator<Alien> alienIterator = alienList.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			alien.freezeBounds = null;
			if (mapper) {
				alien.mapperUpdate();
			}
			else {
				alien.update();
			}
			if (alien.remove || alienTracker.perhapsFreeze(alien, screenBox)) {
				alienIterator.remove();
			}
		}
	}

	private void updateAliens(boolean mapper) {
		recording.clear();

		// add fresh aliens
		Box screenBox = scr.box();
		alienTracker.begin(screenBox);
		updateList(alienTracker.get(Alien.DEPTH_BG_SCENARY), screenBox, mapper);
		updateList(alienTracker.get(Alien.DEPTH_LIFTS_AND_COLLECTABLES), screenBox, mapper);
		updateList(alienTracker.get(Alien.DEPTH_ALIENS), screenBox, mapper);
		if (!mapper && mode != GameMode.COMPLETE) {
			player.draw();
		}
		updateList(alienTracker.get(Alien.DEPTH_FG_SCENARY), screenBox, mapper);

		//
		// Caveat1: only background Aliens get to move the player around.
		// Caveat2: if any Alien does move him the scrolling for this frame
		// won't know about it (because it has already happened) but you don't
		// notice that because it is not hard scrolling but scrolling based on a
		// SCROLLING_TABLE.
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

	public void drawTheMap() {
		ScreenOrdinate ix = scr.scrOrdX;
		ScreenOrdinate iy = scr.scrOrdY;

		int[] blockRow = new int[ix.blockCount];
		int pixelDestY = iy.initialPixelDestination;
		for (int loopY = 0; loopY < iy.blockCount; loopY++) {
			for (int loopX = 0; loopX < ix.blockCount; loopX++) {
				blockRow[loopX] = gameMap.fastGetBlock(ix.mapSourceInBlocks + loopX, iy.mapSourceInBlocks + loopY);
			}
			blockSet.blocksHolder.draw(blockRow, ix.initialPixelDestination, pixelDestY);
			pixelDestY += Const.BLOCK_SIZE;
		}
	}

	public void updateEverything() {
		// System.gc();
		if (usingMapper) {
			mapper.run();
		}
		else {
			int k = keyboard.justPressed();
			if (k == Mapper.MAPPER_KEY) {
				System.out.println("STARTING MAPPER");
				usingMapper = true;
				scr.setMapBoundsInPixels(WHOLE_MAP_BOUNDS_IN_PIXELS);

				gameMap.applyCompress(blockSet.wi.blockRandomisationTable);
				if (mapper == null) {

					for (String a : alienInfoMap.queryAnimList()) {
						animsPool.load(a);
					}

					mapper = new Mapper(alienInfoMap, animsPool, gameMap, this, mouse, keyboard, gc, fonts.debugFont);
				}
				setScreenPosition(getScreenPosition());
				mapper.init();
			}
			else {
				dispatchMode();
			}
		}
	}

	private void dispatchMode() {
		if (getStick().testJustPressed(Joystick.FIRE)) {
			firePressed = true;
		}

		if (mode == GameMode.COMPLETE) {
			modeComplete();
		}
		else if (mode == GameMode.START) {
			modeStart();
		}
		else if (mode == GameMode.PAUSED) {
			modePaused();
		}
		else {
			if (teleportTimer != 0) {
				teleportTimer--;
				drawTeleportEffect();
				drawHudAndBorders(false);
				if (teleportTimer == TELEPORT_TIME / 2) {
					player.c = teleportDestination.copy();
					pickTheBestBounds();
					scr.snapTo(player.c);
				}
			}
			else {
				if (pauseAntiAutofire()) {
					captureRecording();
					mode = GameMode.PAUSED;
					dispatchMode();
				}
				else if (completed) {
					captureRecording();
					dimFade.target(Curtain.CLOSED);

					hole.setCentre(getPlayerCentre());
					hole.target(Curtain.CLOSED);
					hole.setRate(4);

					String text = Messages.levelComplete(pl.worldNum, pl.stageNum, pl.title, gemsCollected, gemsTotal
							- gemsCollected, timeRemaining / Const.FPS, player.gotStar());
					createStatusScreen(text);

					cr = new Coroutine("timeBonus") {
						@Override
						public void run() {
							// wait around a bit
							pause(60);

							//
							// turn time into score
							//
							int fastScore = 0;
							while (timeRemaining != 0) {
								if (firePressed) {
									fastScore += 10;
								}
								else {
									awardScore(10, null);
									playSoundEffect("tink");
									pause(4);
								}
								timeRemaining = Math.max(0, timeRemaining - Const.FPS);
							}
							awardScore(fastScore, null);

							// a pause so you get to look at it
							pause(25);

							//
							// wait for fire
							//
							while (!firePressed) {
								pause();
							}

							//
							// fade to black
							//
							totalFade.target(Curtain.CLOSED);
							while (!totalFade.isDone()) {
								pause();
							}
						}
					};

					ah.startMusic(2);

					mode = GameMode.COMPLETE;
					firePressed = false;
					frameNumber = 0;

					dispatchMode();
				}
				else {
					modeMainGame();
				}
			}
		}
	}

	private void drawTeleportEffect() {
		gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xffffffff);
	}

	private void modePaused() {
		horizon.draw();
		drawTheMap();
		for (SpriteRecord sr : recording) {
			directDrawSprite(sr.c, sr.s, sr.drawInWhite);
		}
		if (isExitOpen()) statusDisplay.drawExitOpen();

		hole.draw();
		statusDisplay.drawPaused();
		drawHudAndBorders(false);

		if (pauseAntiAutofire()) {
			mode = GameMode.PLAYING;
		}
	}

	private void modeStart() {
		drawTitles(false);
		if (getStick().testJustPressed(Joystick.FIRE)) {
			dimFade.target(Curtain.OPEN);
			mode = GameMode.PLAYING;
			ah.startMusic(1);
		}
	}

	private void drawTitles(boolean textOverHole) {
		horizon.draw();
		drawTheMap();
		for (SpriteRecord sr : recording) {
			directDrawSprite(sr.c, sr.s, sr.drawInWhite);
		}
		dimFade.update();
		if (textOverHole) {
			hole.update();
			statusScreen.update();
		}
		else {
			statusScreen.update();
			hole.update();
		}
		totalFade.update();
		drawHudAndBorders(true);
	}

	private void modeComplete() {
		frameNumber++;

		drawTitles(true);

		try {
			cr.step();
		}
		catch (CoTerminated ct) {
			levelNumber++;
			initLevel();

			// we we can't put GL stuff in the coroutine coz its another thread
			// and GL is emphatically single threaded
			// freeStatusScreen();
		}
	}

	private void modeMainGame() {
		frameNumber++;

		int timeDec = player.isStunned() ? 3 : 1;
		timeRemaining = Math.max(timeRemaining - timeDec, 0);

		playerSpriteTopLeft = null;
		player.move();
		assert playerSpriteTopLeft != null;

		if (CTC_HARD_SCROLLING) {
			scr.snapTo(player.c);
		}
		else {
			scr.scrollTo(player.c);
		}

		horizon.draw();
		drawTheMap();

		updateAliens(false);

		dimFade.update();

		if (isExitOpen()) statusDisplay.drawExitOpen();
		drawHurryUp();

		if (teleportTimer != 0) {
			drawTeleportEffect();
		}

		hole.update();
		drawHudAndBorders(false);

		// gc.fillRectangle(gc.screenWidth() / 2, 0, 1, 1000,
		// 0xff000000);
		// gc.fillRectangle(0, gc.screenHeight() / 2, 1000, 1,
		// 0xff000000);
	}

	private void drawBorders() {
		// draw borders on the playing area if the map is small
		ScreenOrdinate lr = scr.scrOrdX;
		if (lr.highBorderStart >= 0) {
			gc.fillRectangle(0, 0, lr.initialPixelDestination, gc.screenHeight(), BORDER_COLOR);
			gc.fillRectangle(lr.highBorderStart, 0, gc.screenWidth(), gc.screenHeight(), BORDER_COLOR);
		}
		ScreenOrdinate tb = scr.scrOrdY;
		if (tb.highBorderStart >= 0) {
			gc.fillRectangle(0, 0, gc.screenWidth(), tb.initialPixelDestination, BORDER_COLOR);
			gc.fillRectangle(0, tb.highBorderStart, gc.screenWidth(), gc.screenHeight(), BORDER_COLOR);
		}
	}

	private boolean pauseAntiAutofire() {
		boolean k = keyboard.isDown(Keyboard.KEY_P);
		boolean answer = k & !wasPauseKeyPressedLastFrame;
		wasPauseKeyPressedLastFrame = k;
		return answer;
	}

	void drawHudAndBorders(boolean supressHurryUp) {
		drawBorders();
		drawHud(supressHurryUp);
	}

	private void drawHud(boolean supressHurryUp) {
		int showGems = gemsNeeded - gemsCollected;
		if (isExitOpen()) {
			showGems = gemsTotal - gemsCollected;
		}
		hud.update(score, timeRemaining, supressHurryUp ? false : isHurryUp(), showGems, isExitOpen(), lives);
	}

	private boolean isHurryUp() {
		return timeRemaining < 6 * Const.FPS;
	}

	private void drawHurryUp() {
		if (isHurryUp()) {
			int flashRate = 20;
			if ((timeRemaining % flashRate) < (flashRate / 2)) {
				statusDisplay.drawHurryUp();
			}
		}
	}

	private void initLevel() {
		AlienFactory af = new AlienFactory(alienInfoMap);
//		int a = 1;
//		while (a == 1) {

			System.out.println("Loading level " + levelNumber);

			pl = new PersistedLevel();

			pl.populateFromLevelInfo(af, levelNumber);
//			pl.saveNew();
//			levelNumber++;
//		}

		worldName = alienInfoMap.getWorldName();

		alienTracker = new AlienTracker();

		List<Alien> aliens = pl.getAliens();

		PlayerAlien playerPos = null;
		for (Alien alien : aliens) {
			if (alien instanceof PlayerAlien) {
				playerPos = (PlayerAlien) alien;
			}
		}

		// work out what Anims we need
		TreeSet<String> animsNeeded = new TreeSet<String>();
		whatAnimsDoTheyNeed(aliens, animsNeeded);
		animsNeeded.add("0tt");
		animsNeeded.add("0life");
		alienInfoMap.collectPreloadNames(animsNeeded);

		// unload what we no longer need
		// load what we do need
		animsPool.unloadReload(animsNeeded);

		// connect the anims to the aliens
		// and load the aliens into the world
		for (Alien alien : aliens) {
			alien.connect(animsPool);
			load(alien);
		}

		createHorizon(pl.horizon);
		if (blockSet == null || !worldName.equals(blockSet.worldName)) {
			reloadBlockSet();
		}

		player = new Player(this, animsPool.expect("0tt"), playerPos.c, playerPos.goLeft);
		gameMap = pl.gameMap;

		pickTheBestBounds();

		player.move();
		scr.snapTo(player.c);

		gameMap.applyShuffle(blockSet.wi.blockRandomisationTable);

		gemsTotal = countGems();
		System.out.println("Gems:" + gemsTotal);
		gemsNeeded = pl.gemsNeeded;
		gemsCollected = 0;

		timeRemaining = pl.timeGiven * Const.FPS + Const.FPS - 1;

		if (hud == null) {
			Anims lifeAnims = animsPool.expect("0life");
			hud = new HeadUpDisplay(gc, fonts.font, lifeAnims.find(0).sprites[0]);
			statusDisplay = new StatusDisplay(gc, fonts.font);
		}

		completed = false;
		mode = GameMode.START;

		captureRecording();

		hole = new Aperture(gc);
		hole.setCentre(getPlayerCentre());
		hole.current(Curtain.CLOSED);
		hole.target(Curtain.OPEN);

		dimFade = new Fade(gc, 0x50, 0.25f);
		dimFade.current(Curtain.CLOSED);
		dimFade.target(Curtain.CLOSED);

		totalFade = new Fade(gc, 0xff, 1f);
		totalFade.current(Curtain.OPEN);
		totalFade.target(Curtain.OPEN);

		ah.loadMusic(2, "levelcomplete");

		ah.loadMusic(1, worldName);

		ah.loadMusic(0, "levelbegin");
		ah.startMusic(0);

		String text = Messages.levelStart(pl.worldNum, pl.stageNum, pl.title, pl.gemsNeeded, gemsTotal, pl.timeGiven);
		createStatusScreen(text);
	}

	/**
	 * The best map bounds are the smallest (i.e. the most specific) bounds that
	 * the player is inside. This allows the map designer to fence of small
	 * areas in a larger map. The player can then teleport such a small area and
	 * the {@link MapBoundsAlien} will keep him from seeing the larger map.
	 */
	private void pickTheBestBounds() {
		final ArrayList<Box> boxes = new ArrayList<Box>();
		alienTracker.visitAll(new Visitor<Alien>() {
			@Override
			public void visit(Alien a) {
				if (a instanceof MapBoundsAlien) {
					Box b = ((MapBoundsAlien) a).bounds.copy();
					b.snapOutTo(Const.BLOCK_SIZE);
					boxes.add(b);
				}
			}
		});
		// what is the smallest one that has the player in it?
		Box bounds = WHOLE_MAP_BOUNDS_IN_PIXELS;
		long bestArea = Long.MAX_VALUE;
		for (Box box : boxes) {
			if (box.inside(player.c) && box.area() < bestArea) {
				bounds = box;
				bestArea = box.area();
			}
		}
		// that is the one for us!
		scr.setMapBoundsInPixels(bounds);
	}

	private Coord getPlayerCentre() {
		return getPlayerPosition().sub2(getScreenPosition()).add2(new Coord(0, (ttSprite.h / 2) - ttSprite.handleY));
	}

	private void captureRecording() {
		record = true;
		updateAliens(false);
		record = false;
	}

	private void whatAnimsDoTheyNeed(List<Alien> aliens, Set<String> animsNeeded) {
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
		c = c.div2(Const.BLOCK_SIZE);
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
		timeRemaining /= Const.FPS;
		timeRemaining = Math.min(timeRemaining + seconds, 99);
		timeRemaining *= Const.FPS;
		timeRemaining += Const.FPS - 1;
	}

	private int countGems() {
		AlienCounter ac = new AlienCounter(GemAlien.class);
		alienTracker.visitAll(ac);
		return ac.count();
	}

	@Override
	public void awardExtraLife() {
		if (lives != 9) {
			lives++;
		}
	}

	@Override
	public boolean isOffTheBottom(Coord c) {
		// *2 to be generous
		int offY = scr.position().y + gc.screenHeight() * 2;
		return c.y > offY;
	}

	@Override
	public void levelCompleted() {
		completed = true;
	}

	@Override
	public boolean showText() {
		return !record;
	}

	
	// ---------------------------------------------------------------------------
	// MAPPER SPECIFICS
	// ---------------------------------------------------------------------------

	@Override
	public void quitMapper(Coord mousePos) {
		player.resetTo(mousePos);
		gameMap.applyShuffle(blockSet.wi.blockRandomisationTable);

		System.out.println("STOPPING MAPPER");
		usingMapper = false;
		// alienTracker.reclassify();
		pickTheBestBounds();
	}




	@Override
	public Coord getScreenPosition() {
		return scr.position();
	}

	@Override
	public void setScreenPosition(Coord c) {
		scr.setPosition(c);
	}

	private void drawGrid() {
		ScreenOrdinate ix = scr.scrOrdX;
		ScreenOrdinate iy = scr.scrOrdY;

		int col = 0x40ffffff;
		for (int q = 0; q < iy.blockCount; q++) {
			int dx = ix.initialPixelDestination;
			int dy = iy.initialPixelDestination + q * Const.BLOCK_SIZE;
			int s = ix.blockCount * Const.BLOCK_SIZE;
			gc.fillRectangle(dx, dy, s, 1, col);
			gc.fillRectangle(dx, dy + Const.BLOCK_SIZE - 1, s, 1, col);
		}

		for (int q = 0; q < ix.blockCount; q++) {
			int dx = ix.initialPixelDestination + q * Const.BLOCK_SIZE;
			int dy = iy.initialPixelDestination;
			int s = iy.blockCount * Const.BLOCK_SIZE;
			gc.fillRectangle(dx, dy, 1, s, col);
			gc.fillRectangle(dx + Const.BLOCK_SIZE - 1, dy, 1, s, col);
		}
	}


	@Override
	public void drawForMapper() {
		drawGrid();
		drawTheMap();
		updateAliens(true);
	}

	@Override
	public Anim mapperLoadAnim(String animsName) {
		Anims anims = animsPool.expect(animsName);
		Anim anim = anims.find(0);
		return anim;
	}

	@Override
	public Alien findNearestAlien(Coord c) {
		NearestAlienFinder n = new NearestAlienFinder(c);
		alienTracker.visitAll(n);
		return n.getAnswer();
	}

	@Override
	public void setBlockConfig(BlockSet.Config c) {
		blocksetConfig = c;
		reloadBlockSet();
	}

	@Override
	public BlocksHolder getBlocksHolder() {
		return blockSet.blocksHolder;
	}

	@Override
	public void reinstate(Alien alien) {
		alien.reinstate();
		alienTracker.delayedAdd(alien);
	}

	// ---------------------------------------------------------------------------
	// (RE)LOAD AND FREE
	// ---------------------------------------------------------------------------
	
	private void reloadBlockSet() {
		freeBlocksSet();
		blockSet = new BlockSet(gc, worldName, blocksetConfig);
	}

	private void freeBlocksSet() {
		if (blockSet != null) {
			blockSet.dispose();
			blockSet = null;
		}
	}

	private void createStatusScreen(String text) {
		freeStatusScreen();
		statusScreen = new StatusScreen(gc, fonts.font);
		OsdParser osdParser = new OsdParser(statusScreen);
		osdParser.parse(text);
		statusScreen.done();
	}

	private void freeStatusScreen() {
		if (statusScreen != null) {
			statusScreen.dispose();
			statusScreen = null;
		}
	}

	private void createHorizon(int horizon2) {
		freeHorizon();
		horizon = gc.loadHorizon(TTResource.horizon(pl.horizon));
	}

	private void freeHorizon() {
		if (horizon != null) {
			horizon.dispose();
			horizon = null;
		}
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

