package com.nney.tt;

import java.util.Iterator;
import java.util.List;
import java.util.Random;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.ArrowAlien;
import com.nney.tt.aliens.BattAlien;
import com.nney.tt.aliens.BearAlien;
import com.nney.tt.aliens.BeeAlien;
import com.nney.tt.aliens.BigGemAlien;
import com.nney.tt.aliens.BirdAlien;
import com.nney.tt.aliens.ClockAlien;
import com.nney.tt.aliens.ExitAlien;
import com.nney.tt.aliens.FlameAlien;
import com.nney.tt.aliens.GhostAlien;
import com.nney.tt.aliens.HoneyAlien;
import com.nney.tt.aliens.HugeGemAlien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.PortraitAlien;
import com.nney.tt.aliens.PlainLiftAlien;
import com.nney.tt.aliens.PurpleGemAlien;
import com.nney.tt.aliens.ScoreGivingAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.aliens.ShieldAlien;
import com.nney.tt.aliens.SineLiftAlien;
import com.nney.tt.aliens.SpriteAlien;
import com.nney.tt.aliens.StarAlien;
import com.nney.tt.aliens.StopAlien;
import com.nney.tt.aliens.TeleportAlien;
import com.nney.tt.aliens.TextAlien;
import com.nney.tt.aliens.TrampolineAlien;
import com.nney.tt.aliens.WingAlien;
import com.nney.tt.aliens.YellowBirdAlien;
import com.nney.tt.aliens.YellowGemAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.gfx.PrerenderedText;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.mapper.Mapper;
import com.nney.tt.mapper.NearestAlienFinder;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsDefPool;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.LineInfo;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class World implements AlienServices, WorldServicesToMapper {

	public static final Box WHOLE_MAP_BOUNDS_IN_PIXELS = Box.fromTopLeftAndSize(0, 0, GameMap.MAP_WIDTH
			* Const.BLOCK_SIZE, GameMap.MAP_HEIGHT * Const.BLOCK_SIZE);

	final private GraphicsContext gc;

	// lift
	private static final String CTC_WORLD = "w";
	private static final int CTC_MAP = 1;

	// ladders & ice
	// private static final String CTC_WORLD = "i";
	// private static final int CTC_MAP = 0;

	// private static final String CTC_WORLD = "g";
	// private static final int CTC_MAP = 0;

	// /**
	// * Compile time configuration: play in level containing only the map.
	// */
	// private static final boolean CTC_TUMBLE_WEEDS = false;

	/**
	 * Compile time configuration: the screen follows the player <b>exactly</b>.
	 */
	private static final boolean CTC_HARD_SCROLLING = false;

	private BlocksHolder blocksHolder;

	final private Random rnd = new Random(5);
	private Font debugFont;
	private Font font;

	private Coord screen = new Coord();
	private MasksHolder maskHolder;
	private Player player;

	private GameMap gameMap;
	private Box liveScrollBoundsInPixels;

	private Box mapBoundsInBlocks;

	private AlienTracker alienTracker = new AlienTracker();

	private int frameNumber;

	private Sprite ttSprite;
	private Coord ttPos;

	private int score = 0;
	private int oldScore = -1;

	private PrerenderedText scoreHeadingText;

	private PrerenderedText scoreText;

	private int gemCounter;

	private WorldInformation wi;

	private AlienInfoMap alienInfoMap;
	private AnimsPool animsPool;
	private int teleAttempt;

	private final Joystick joystick;
	private Horizon horizon;

	private final Keyboard keyboard;

	private String worldName = CTC_WORLD;

	// mapper vars
	private boolean usingMapper;

	private Mapper mapper;

	private Pointer mouse;

	private boolean configShowInvisible;

	private boolean configSeeMasks;

	private int whiteTimer;

	private int timeRemaining;

	public World(GraphicsContext gc, Joystick joystick, Keyboard keyboard, Pointer mouse) {
		this.gc = gc;
		this.joystick = joystick;
		this.keyboard = keyboard;
		this.mouse = mouse;

		initFonts();

		AlienInfoMap aim = new AlienInfoMap();
		aim.add(new AlienInfo(2, "0ygem", YellowGemAlien.class));
		aim.add(new AlienInfo(3, "0pgem", PurpleGemAlien.class));
		aim.add(new AlienInfo(4, "0exit", ExitAlien.class));
		aim.add(new AlienInfo(5, "0shld", ShieldAlien.class));
		aim.add(new AlienInfo(6, "0bgem", BigGemAlien.class));
		aim.add(new AlienInfo(7, "0clok", ClockAlien.class));
		aim.add(new AlienInfo(8, "0arru", ArrowAlien.class));
		aim.add(new AlienInfo(9, "0arrd", ArrowAlien.class));
		aim.add(new AlienInfo(10, "0arrl", ArrowAlien.class));
		aim.add(new AlienInfo(11, "0arrr", ArrowAlien.class));
		aim.add(new AlienInfo(12, "0tele", TeleportAlien.class));
		aim.add(new AlienInfo(14, "0wing", WingAlien.class));
//		aim.add(new AlienInfo(15, null, FloorFailAlien.class));			// special1 for w6.map
		aim.add(new AlienInfo(18, "0cld0", SpriteAlien.class));
		aim.add(new AlienInfo(19, "0cld1", SpriteAlien.class));
		aim.add(new AlienInfo(20, "0cld2", SpriteAlien.class));
		aim.add(new AlienInfo(31, "gwall", SpriteAlien.class));
		aim.add(new AlienInfo(34, null, ScoreGivingAlien.class));
		aim.add(new AlienInfo(36, "gfran", BearAlien.class));
		aim.add(new AlienInfo(37, "gbatt", BattAlien.class));

		aim.add(new AlienInfo(40, "gpic2", SpriteAlien.class));
		aim.add(new AlienInfo(40, "gpic0", PortraitAlien.class));
		aim.add(new AlienInfo(41, "gpic1", PortraitAlien.class));
		aim.add(new AlienInfo(42, "gpic2", SpriteAlien.class));
		aim.add(new AlienInfo(43, "gpic3", PortraitAlien.class));
		aim.add(new AlienInfo(44, "gpic4", PortraitAlien.class));
		aim.add(new AlienInfo(45, "gtrch", SpriteAlien.class));
		aim.add(new AlienInfo(46, "glflm", FlameAlien.class));
		aim.add(new AlienInfo(47, "grflm", FlameAlien.class));
		aim.add(new AlienInfo(48, "gghst", GhostAlien.class));
		aim.add(new AlienInfo(62, "whone", HoneyAlien.class));
		// TODO: 00: should the score just be part of AlienInfoMap???
		aim.add(new AlienInfo(63, "wabee", BeeAlien.class));
		aim.add(new AlienInfo(65, "wfce0", SpriteAlien.class));
		aim.add(new AlienInfo(66, "wfce1", SpriteAlien.class));
		aim.add(new AlienInfo(67, "wfce2", SpriteAlien.class));
		aim.add(new AlienInfo(68, "wflr0", SpriteAlien.class));
		aim.add(new AlienInfo(69, "wflr1", SpriteAlien.class));
		aim.add(new AlienInfo(70, "wtrk0", SpriteAlien.class));
		aim.add(new AlienInfo(71, "wtrk1", SpriteAlien.class));
		aim.add(new AlienInfo(72, "wlog0", SineLiftAlien.class));
		aim.add(new AlienInfo(73, "wtrmp", TrampolineAlien.class));
		aim.add(new AlienInfo(74, "wybrd", YellowBirdAlien.class));
		aim.add(new AlienInfo(75, "wbird", BirdAlien.class));
		aim.add(new AlienInfo(76, "wbear", BearAlien.class));
		aim.add(new AlienInfo(86, "0hgem", HugeGemAlien.class));
		aim.add(new AlienInfo(93, "wfnsh", SpriteAlien.class));
		aim.add(new AlienInfo(95, "0star", StarAlien.class));
		aim.add(new AlienInfo(13, "0stop", StopAlien.class));
		aim.add(new AlienInfo(-1, "0scor", ScoreNoticeAlien.class));
		aim.add(new AlienInfo(-1, "0magc", MagicDustAlien.class));
		aim.add(new AlienInfo(200, "glift", PlainLiftAlien.class));

		alienInfoMap = aim;

		init();
	}

	private static String characterRangeHelper(int begin, int end) {
		StringBuilder sb = new StringBuilder();
		for (int x = begin; x < end; x++) {
			sb.append((char) x);
		}
		return sb.toString();
	}

	private void initFonts() {
		debugFont = gc.createFont(OpenableTools.mustLoad(TTResource.font("topaz")), 8, 8, false,
				characterRangeHelper(0, 128));

		font = gc.createFont(OpenableTools.mustLoad(TTResource.font("font2")), 16, 11, true,
				"abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()' ");
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
		return maskHolder.inTheGround(block, c.x & 15, c.y & 15);
	}

	/**
	 * What is there?
	 * 
	 * @param collisionBox
	 *            The pixel location being queried.
	 * @return The kind of block that is there. e.g. "magic" or "ladder" or any
	 *         text string used in the configuration of a
	 *         {@link BlockInformation} object.
	 */
	private String getBlockInfo(Coord c) {
		int block = getBlock(c);
		return wi.blockInformation.get(block);
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
		else {
			gemCounter--;
			System.out.println(gemCounter + " gems left!");
		}
		giveScore(score, noticeLocation);
	}

	@Override
	public boolean isExitOpen() {
		return gemCounter == 0;
	}

	// ---------------------------------------------------------------------------
	// SCROLLING

	/**
	 * A curve of sorts that dictates how much to {@link #scrollScreenTo(Coord)}
	 * pulls tracked {@link Coord} back into the centre (given its distance from
	 * the centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
			16 };

	private static int limit(int current, int min, int max) {
		if (current < min) {
			current = min;
		}
		if (current > max) {
			current = max;
		}
		return current;
	}

	private static int shrinkDelta(int delta) {
		boolean neg = false;
		if (delta < 0) {
			neg = true;
			delta = -delta;
		}
		delta = Math.min(delta, SCROLLING_TABLE.length - 1);
		int shrunkDelta = SCROLLING_TABLE[delta];
		if (neg) {
			shrunkDelta = -shrunkDelta;
		}
		return shrunkDelta;
	}

	private Coord screenDest(Coord c) {
		return c.copyAndAdd(-gc.screenWidth() / 2, -gc.screenHeight() * 11 / 16);
	}

	private void limitScreenPosition() {
		Box b = liveScrollBoundsInPixels;
		screen.x = limit(screen.x, b.left, (b.right + 1) - gc.screenWidth());
		screen.y = limit(screen.y, b.top, (b.bottom + 1) - gc.screenHeight());
	}

	private static int scrollOrd(int current, int dest) {
		current += shrinkDelta(dest - current);
		return current;
	}

	/**
	 * Scroll the screen gently towards the given position.
	 */
	private void scrollScreenTo(Coord c) {
		Coord sd = screenDest(c);
		screen.x = scrollOrd(screen.x, sd.x);
		screen.y = scrollOrd(screen.y, sd.y);
		limitScreenPosition();
	}

	/**
	 * Snap the screen instantly to the given position.
	 */
	@Override
	public void snapScreenTo(Coord c) {
		screen = screenDest(c);
		limitScreenPosition();
	}

	// ---------------------------------------------------------------------------
	// DRAWING

	@Override
	public void drawSprite(final Coord c, final Sprite s) {
		drawSprite(c, s, false);
	}

	@Override
	public void drawSprite(Coord c, final Sprite s, boolean drawWhite) {
		final int x = c.x - screen.x;
		final int y = c.y - screen.y;
		s.draw(x, y, drawWhite);
	}

	@Override
	public void registerPlayerSpriteForAlienColisions(Coord c, Sprite s) {
		ttPos = c.copy();
		ttPos.x -= s.handleX;
		ttPos.y -= s.handleY;
		ttSprite = s;
	}

	@Override
	public Coord getPlayerPosition() {
		return player.c;
	}

	@Override
	public void validatePlayerPosition(Coord c) {
		Box m = liveScrollBoundsInPixels.copy();
		m.shrink(6);
		m.constrain(c);
	}

	@Override
	public int getFrameNumber() {
		return frameNumber;
	}

	// TODO: unused
	@Override
	public boolean collideAlienDeluxePaintBoxWithPlayer(Coord alienPos, Box deluxePaintBox) {
		int diffX = player.c.x - alienPos.x;
		int diffY = player.c.y - alienPos.y;

		int deluxePaintX = 160 + diffX;
		int deluxePaintY = 128 - diffY;
		if (deluxePaintX + 8 >= deluxePaintBox.left) {
			if (deluxePaintX - 8 <= deluxePaintBox.right) {
				if (deluxePaintY <= deluxePaintBox.top) {
					if (deluxePaintY + 30 >= deluxePaintBox.bottom) {
						return true;
					}
				}
			}
		}
		return false;
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

	// TODO: unused
	@Override
	public boolean collideAlienWithPlayerBounds(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - ttPos.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - ttPos.y;
			return dy < ttSprite.h && dy > (-alienSprite.h);
		}
		return false;
	}

	@Override
	public boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - ttPos.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - ttPos.y;
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
		return wi.ladderInformation;
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
	public void giveScore(int amount, Coord location) {
		score += amount;
		if (location != null) {
			addNewAlien(new ScoreNoticeAlien(amount, location.copy()));
		}
	}

	@Override
	public void magicDust(Coord location) {
		addNewAlien(new MagicDustAlien(location.copy()));
	}

	// ---------------------------------------------------------------------------
	// UPDATING OF THINGS

	/**
	 * Compile time configuration: Only have instantiate once instance of each
	 * alien type that is present on a level (the others are ignored).
	 */
	private static final boolean CTC_ITEM_ONCE = false;

	@Override
	public Alien createAlien(int typeCode) {
		assert typeCode >= 0;

		AlienInfo alienInfo = alienInfoMap.getByType(typeCode);
		if (alienInfo != null) {
			if (CTC_ITEM_ONCE) {
				alienInfoMap.removeByType(typeCode);
			}
			Alien alien = alienInfo.instantiate();
			String animsName = alienInfo.animsName;
			if (animsName != null) {
				alien.connectAnims(loadAnims(animsName));
			}
			alien.typeCode = typeCode;
			return alien;
		}

		System.out.println("Unknown Alien Type:" + typeCode);
		TextAlien alien = new TextAlien();
		alien.setText(String.format("%d", typeCode));
		return alien;
	}

	@Override
	public Anims loadAnims(String animsName) {
		return animsPool.load(animsName);
	}

	private void addNewAlien(Alien alien) {
		alienInfoMap.giveTypeCodeAndConnectAnims(alien, animsPool);
		alien.srv = this;
		alien.onLoaded();
		alienTracker.delayedAdd(alien);
	}

	@Override
	public void loadAlienIntoWorld(Alien alien) {
		alien.srv = this;
		alien.onLoaded();
		alienTracker.delayedAdd(alien);
	}

	@Override
	public void reinstateAlien(Alien alien) {
		alien.remove = false;
		alienTracker.delayedAdd(alien);
	}

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

	@Override
	public void drawAliensForMapper() {
		updateAliens(true);
	}

	private void updateAliens(boolean mapper) {
		// add fresh aliens
		Box screenBox = Box.fromTopLeftAndSize(screen, gc.screenWidth(), gc.screenHeight());
		alienTracker.begin(screenBox);
		updateList(alienTracker.getBackgroundList(), screenBox, mapper);
		if (!mapper) {
			player.draw();
		}
		updateList(alienTracker.getForegroundList(), screenBox, mapper);

		//
		// Caveat1: only the background Alien gets to move the player around.
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

	private void updateScore() {
		if (score != oldScore) {
			scoreHeadingText = font.preDraw(0xffffff00, 0, "score");
			scoreText = font.preDraw(0xffffffff, 0, String.format("%08d", score));
		}
		scoreHeadingText.draw((gc.screenWidth() - scoreHeadingText.width()) / 2, 6);
		scoreText.draw((gc.screenWidth() - scoreText.width()) / 2, 6 + 14);
	}

	private void drawTheMap() {
		MapDrawingInfo ix = new MapDrawingInfo(screen.x, gc.screenWidth());
		MapDrawingInfo iy = new MapDrawingInfo(screen.y, gc.screenHeight());
		// ix.checkForOverread(mapBounds.xEnd(), GameMap.MAP_WIDTH);
		// iy.checkForOverread(mapBounds.yEnd(), GameMap.MAP_HEIGHT);

		int[] blockRow = new int[ix.blockCount];

		int pixelDestY = iy.initialPixelDestination;
		for (int loopY = 0; loopY < iy.blockCount; loopY++) {
			for (int loopX = 0; loopX < ix.blockCount; loopX++) {
				blockRow[loopX] = gameMap.fastGetBlock(ix.mapSourceInBlocks + loopX, iy.mapSourceInBlocks + loopY);
			}
			blocksHolder.draw(blockRow, ix.initialPixelDestination, pixelDestY);
			pixelDestY += Const.BLOCK_SIZE;
		}
	}

	public void computeMapBounds() {
		if (usingMapper) {
			liveScrollBoundsInPixels = WHOLE_MAP_BOUNDS_IN_PIXELS;
		}
		else {
			liveScrollBoundsInPixels = mapBoundsInBlocks.copy();
			liveScrollBoundsInPixels.mult(Const.BLOCK_SIZE);
		}
	}

	public void updateEverything() {
		if (usingMapper) {
			mapper.run();
		}
		else {
			if (keyboard.justPressed() == Mapper.MAPPER_KEY) {
				usingMapper = true;
				computeMapBounds();
				gameMap.applyCompress(wi.blockRandomisationTable);
				if (mapper == null) {
					mapper = new Mapper(alienInfoMap, gameMap, this, mouse, keyboard, gc, debugFont);
				}
				mapper.init();
			}
			else {
				frameNumber++;
				if (whiteTimer != 0) {
					whiteTimer--;
					gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xffffffff);
				}
				else {
					ttPos = null;
					player.move();
					assert ttPos!=null;
					
					if (CTC_HARD_SCROLLING) {
						snapScreenTo(player.c);
					}
					else {
						scrollScreenTo(player.c);
					}

					horizon.draw();
					drawTheMap();
					updateAliens(false);
					updateScore();
				}
			}
		}
	}

	private void init() {
		Openable ho = TTResource.horizon(1);
		horizon = gc.loadHorizon(ho);

		animsPool = new AnimsPool(gc, new AnimsDefPool());
		alienInfoMap.doPreLoad(animsPool);

		wi = WorldInformation.load(worldName);
		loadBlocks();

		Openable mapOpenable = TTResource.map(worldName, CTC_MAP);

		PersistedMap pm = new PersistedMap();
		pm.loadLegacy(this, mapOpenable);

		for (Alien a : pm.aliens) {
			loadAlienIntoWorld(a);
		}
		mapBoundsInBlocks = pm.mapBounds;

		Anims playerAnims = animsPool.load("0tt");
		player = new Player(this, playerAnims, new Coord(pm.playerX, pm.playerY), pm.playerGoLeft);
		gameMap = pm.gameMap;

		computeMapBounds();
		snapScreenTo(player.c);

		gameMap.applyShuffle(wi.blockRandomisationTable);
	}

	private void loadBlocks() {
		Openable blocksGraphics = TTResource.blocks(worldName);
		Openable masksGraphics = TTResource.blockMask(worldName);

		BlockSource bs = new BlockSource(configSeeMasks ? masksGraphics : blocksGraphics, Const.BLOCK_SIZE);
		if (!configShowInvisible) bs.doBlockHiding(wi.invisibleBlockHiding);
		blocksHolder = gc.createBlocksHolder(bs);
		maskHolder = new MasksHolder(Const.BLOCK_SIZE, masksGraphics);
	}

	@Override
	public void teleportTo(Coord destination) {
		// if we didn't try teleporting last frame
		if (teleAttempt + 1 != frameNumber) {
			// do it
			player.c = destination.copy();
			snapScreenTo(destination);
			whiteTimer = 10;
		}
		teleAttempt = frameNumber;
		// (this stops us vibrating between two teleports)
	}

	// ---------------------------------------------------------------------------
	// MAPPER SERVICES
	//
	// It's how the Mapper attaches to the World
	//

	@Override
	public void quitMapper(Coord mousePos) {
		player.resetTo(mousePos);
		gameMap.applyShuffle(wi.blockRandomisationTable);

		usingMapper = false;
		alienTracker.reclassify();
		computeMapBounds();
	}

	@Override
	public void drawMap() {
		// horizon.draw();
		drawTheMap();
	}

	@Override
	public void moveScreen(Coord delta) {
		System.out.println("DELTA" + delta);
		screen.add(delta);
		limitScreenPosition();
	}

	@Override
	public Coord getScreenPosition() {
		return screen;
	}

	@Override
	public Alien findNearestAlien(Coord c) {
		NearestAlienFinder n = new NearestAlienFinder(c);
		alienTracker.visitVisible(n);
		return n.getAnswer();
	}

	@Override
	public void toggleSeeMasks() {
		configSeeMasks = !configSeeMasks;
		loadBlocks();
	}

	@Override
	public void toggleShowInvisible() {
		configShowInvisible = !configShowInvisible;
		loadBlocks();
	}

	@Override
	public BlocksHolder getBlocksHolder() {
		return blocksHolder;
	}

	@Override
	public void setScreenPosition(Coord c) {
		screen = c;
		limitScreenPosition();
	}

	@Override
	public void drawDebugText(Coord c, String text) {
		Coord a = c.sub2(screen);
		int w = debugFont.charWidth() * text.length();
		int h = debugFont.charHeight();
		gc.fillRectangle(a.x, a.y, w, h, 0xff000000);
		debugFont.draw(a.x, a.y, 0xff00ff00, 0, text);
	}

	@Override
	public Box getMapBoundsInBlocks() {
		return mapBoundsInBlocks.copy();
	}

	@Override
	public void setMapBoundsInBlocks(Box mapBoundsInBlocks) {
		this.mapBoundsInBlocks = mapBoundsInBlocks.copy();
	}

	@Override
	public boolean isMapping() {
		return true;
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
	public void extraTime(int seconds) {
		timeRemaining = Math.min(timeRemaining+seconds, 99);
	}
}

// 64: worm - forget it
// 74: ybrd - write it
// 78: scrh ....
// change it to something that prohibits horizontal scrolling, since that is the
// intent .... BUT what do we do about screen width??

// Unknown Alien Type:101
// Unknown Alien Type:102

