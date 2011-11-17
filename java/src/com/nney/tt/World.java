package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import com.nney.coroutines.CoTerminated;
import com.nney.coroutines.Coroutine;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.FallingAlien;
import com.nney.tt.aliens.GemAlien;
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
import com.nney.utils.ListUtil;
import com.nney.utils.Math2;

public class World implements AlienServices, Disposable {
	public class ExitException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

	// 8 map+code: needs lift 0
	// 9 map+code: needs lift 0
	// 10 ok
	// 11 map+code: needs lift 101
	// 12 map: secret area visible
	// 13 map|code: fall through??
	// 14 ok
	// 15 the gallery:
	// -- map: wall priority

	// TODO: code ballon man

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

	final private Random rnd = new Random();

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
	 * decouple updating and actually drawing and leaving a recording sitting
	 * around for whenever we needed it.
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

	private boolean seeMasks;

	private boolean seeHidden;

	private OuterWorld ow;

	private GraphicsContext gc;

	private AudioHub ah;

	private Joystick joystick;

	private Keyboard keyboard;

	private Fonts fonts;

	private AnimsPool animsPool;

	private Coord configuredPlayerStart;

	private String configuredMapText;

	private boolean drawPlayer = true;

	private boolean complete;

	private Coord whereWeExitedTheLevel;

	private LevelInfo levelInfo;

	private boolean configuredCalledFromMapper;

	private boolean didScroll;

	private ParsedJoystickImpl parsedJoystick = new ParsedJoystickImpl();

	private boolean configuredPerformIntro = true;

	private String configuredScriptDestination;

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
						return collisionDetection;
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
						return collisionDetection;
					}
				}
			}
		}
		return false;
	}

	@Override
	public void headBounce(Alien alien, Sprite alienSprite) {
		Coord alienPos = alien.getLocation();
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
						FallingAlien fa = new FallingAlien(alienPos, headScore, raiseScoreNoticeBy, frightAnim);
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
		ow.score += amount;
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

	public void load(Alien alien) {
		alienTracker.delayedAdd(alien);
	}

	// ---------------------------------------------------------------------------

	private void updateList(List<Alien> alienList, Box screenBox) {
		for (Iterator<Alien> alienIterator = alienList.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			alien.freezeBounds = null;
			alien.update();

			Box fb = alien.freezeBounds;
			if (fb!=null) {
				Box s = fb.sub2(getScreenPosition());
				gc.fillRectangle(s.left, s.top, s.width(), s.height(), 0x80ff0000);
			}
			
			if (alien.remove || alienTracker.perhapsFreeze(alien, screenBox)) {
				alienIterator.remove();
			}
		}
	}

	private void updateTheAliens() {
		recording.clear();

		// add fresh aliens
		Box screenBox = scr.box();
		alienTracker.begin(screenBox);
		updateList(alienTracker.getOnScreen(Alien.DEPTH_BG_SCENARY), screenBox);
		updateList(alienTracker.getOnScreen(Alien.DEPTH_LIFTS_AND_COLLECTABLES), screenBox);
		updateList(alienTracker.getOnScreen(Alien.DEPTH_ALIENS), screenBox);
		if (drawPlayer) {
			player.draw();
		}
		updateList(alienTracker.getOnScreen(Alien.DEPTH_FG_SCENARY), screenBox);

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
		drawTheMap();
		for (SpriteRecord sr : recording) {
			directDrawSprite(sr.c, sr.s, sr.drawInWhite);
		}
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

	private boolean pauseAntiAutofire() {
		return pauseKey.next(keyboard.isDown(Keyboard.KEY_P)).pressed();
	}

	void drawHudAndBorders(boolean supressHurryUp) {
		scr.drawBorders(gc);
		drawHud(supressHurryUp);
	}

	private void drawHud(boolean supressHurryUp) {
		int showGems = gemsNeeded - gemsCollected;
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
		for (MapBoundsAlien a : ListUtil.findMany(MapBoundsAlien.class, alienTracker)) {
			Box box = a.bounds.copy();
			box.snapOutTo(Const.BLOCK_SIZE);
			// what is the smallest one that has the player in it?
			if (box.inside(player.c) && box.area() < bestArea) {
				bounds = box;
				bestArea = box.area();
			}
		}
		// that is the one for us!
		System.out.println("Map bounds: " + bounds);
		scr.setMapBoundsInPixels(bounds, bounds);
	}

	private Coord getPlayerCentreOnScreen() {
		return getPlayerPosition().copyAndAdd(0, (ttSprite.h / 2) - ttSprite.handleY).sub2(scr.position());
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

	@Override
	public void levelCompleted(Coord exit) {
		whereWeExitedTheLevel = exit.copy();
	}

	@Override
	public boolean showText() {
		return !record;
	}

	// ---------------------------------------------------------------------------
	// DRAWING A FRAME: BEGIN AND END
	//

	private void begin() {
		// the main game doesn't use events so this is just to drain them
		// i.e. stop them piling up
		keyboard.nextEvent();
		
		if (keyboard.isDown(Keyboard.KEY_ESCAPE)) {
			throw new ExitException();
		}
		firePressed |= Math2.maskTest(joystick.get(), Joystick.FIRE);

		gc.beginDrawing();
	}

	private void end() {
		gc.endDrawing();
	}

	// ---------------------------------------------------------------------------
	// PRINCIPAL METHODS

	void maybePause() {
		if (pauseAntiAutofire()) {
			captureRecording();
			while (!pauseAntiAutofire()) {
				begin();
				drawTheMap();
				for (SpriteRecord sr : recording) {
					directDrawSprite(sr.c, sr.s, sr.drawInWhite);
				}
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
		gameMap = pl.getMap();
		pl = null;

		Coord playerWhere = null;
		boolean playerLeft = false;
		if (configuredPlayerStart == null) {
			PlayerAlien palien = ListUtil.findOne(PlayerAlien.class, aliens);
			if (palien != null) {
				playerWhere = palien.c;
				playerLeft = palien.goLeft;
			}
			else {
				throw new RuntimeException("Need a PlayerAlien to establish player's starting position!");
			}
		}
		else {
			playerWhere = configuredPlayerStart;
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

		// connect the anims to the aliens
		// and load the aliens into the world
		for (Alien alien : aliens) {
			alien.connect(animsPool);
			load(alien);
		}

		horizon = ow.getHorizon(levelInfo.horizon);

		blockSet = ow.loadBlockSet(new BlockSet.Config(worldName, seeMasks, seeHidden));

		player = new Player(this, animsPool.expect("0tt"), playerWhere, playerLeft);

		pickTheBestBounds();

		player.move(parsedJoystick);
		scr.snapTo(player.c);

		gameMap.applyShuffle(blockSet.wi.blockRandomisationTable);

		gemsTotal = ListUtil.count(GemAlien.class, alienTracker);
		gemsNeeded = levelInfo.gemsNeeded;
		gemsCollected = 0;

		timeRemainingInFrames = levelInfo.timeGiven * Const.FPS + Const.FPS - 1;

		assert hud == null;

		Anims lifeAnims = animsPool.expect("0life");
		hud = new HeadUpDisplay(gc, fonts.font, lifeAnims.find(0).sprites[0]);
		statusDisplay = new StatusDisplay(gc, fonts.font);
	}

	private void performIntro() {
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

		String text = Messages.levelStart(ow.levelNumber + 1, levelInfo.title, levelInfo.gemsNeeded, gemsTotal,
				levelInfo.timeGiven);
		createStatusScreen(text);

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

	private void oneMainFrame() {
		checkTeleportation();

		maybePause();

		if (keyboard.isDown(Keyboard.KEY_D)) {
			timeRemainingInFrames = 0;
		}

		int timeDec = player.isStunned() ? 3 : 1;
		timeRemainingInFrames = Math.max(timeRemainingInFrames - timeDec, 0);
		if (timeRemainingInFrames == 0) {
			performLifeDec();
		}
		else {
			//
			// MODE MAIN
			//
			begin();

			int j = joystick.get();
			if (scriptReader != null) j = scriptReader.get();
			if (scriptWriter != null) scriptWriter.put(j);
			mainActions(j);

			dimFade.update();

			if (isExitOpen()) statusDisplay.drawExitOpen();
			drawHurryUp();

			hole.update();
			drawHudAndBorders(false);

			end();

			if (whereWeExitedTheLevel != null) {
				performOutro();
			}
		}
	}

	private void performLifeDec() {
		collisionDetection = false;

		player.kill();
		// so that twangs him up in the air
		// we need to keep waiting until
		// he is on his arse and the screen has stopped scrolling
		do {
			begin();
			mainActions(0);
			drawHudAndBorders(false);
			end();
		} while (!player.onArse() || didScroll);

		
		final Coord t = getPlayerCentreOnScreen().copyAndAdd(2, -6);
		hole.setCentre(t);
		hole.current(Curtain.OPEN);
		hole.target(Curtain.CLOSED);
		hole.setRate(3);

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

		SlowBoolean ot = new SlowBoolean(true);
		do {
			begin();
			mainActions(0);
			hole.update();
			int p = hole.current();
			if (p > 60) start = true;
			if (start) {
				if (ot.set(false)) {
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

		complete = true;
	}

	// gc.fillRectangle(t.x, 0, 1, 1000, 0xffff00ff);
	// gc.fillRectangle(0, t.y, 1000, 1, 0xffff00ff);

	private void mainActions(int joystickPosition) {
		frameNumber++;

		parsedJoystick.set(joystickPosition);
		player.move(parsedJoystick);

		scrollTheScreen();
		drawTheMap();
		updateTheAliens();
	}

	private void scrollTheScreen() {
		Coord orig = scr.position().copy();
		if (CTC_HARD_SCROLLING) {
			scr.snapTo(player.c);
		}
		else {
			scr.scrollTo(player.c);
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
				player.c = teleportDestination.copy();
				pickTheBestBounds();
				scr.snapTo(player.c);
			}
			end();
		}
	}

	private void performMain() {
		while (!complete) {
			oneMainFrame();
		}
	}

	private void performOutro() {
		drawPlayer = false;
		captureRecording();
		dimFade.target(Curtain.CLOSED);

		hole.setCentre(whereWeExitedTheLevel.sub2(scr.position()));
		hole.target(Curtain.CLOSED);
		hole.setRate(4);

		String text = Messages.levelComplete(ow.levelNumber + 1, levelInfo.title, gemsCollected, gemsTotal
				- gemsCollected, timeRemainingInFrames / Const.FPS, player.gotStar());
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
				while (timeRemainingInFrames != 0) {
					if (firePressed) {
						fastScore += 10;
					}
					else {
						awardScore(10, null);
						playSoundEffect("tink");
						pause(4);
					}
					timeRemainingInFrames = Math.max(0, timeRemainingInFrames - Const.FPS);
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

		firePressed = false;

		boolean done = false;
		while (!done) {
			begin();
			drawTitles(true);

			try {
				cr.step();
			}
			catch (CoTerminated ct) {
				done = true;
			}
			end();
		}

		ow.levelNumber++;
		complete = true;
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

	public void playLevel() {
		try {
			create();
			if (configuredPerformIntro) performIntro();
			performMain();
		}
		catch (ExitException ex) {
		}
		if (scriptWriter != null) {
			TTResource.saveScript(configuredScriptDestination, scriptWriter.save());
		}
		dispose();
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
		ah.stopMusic();
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

