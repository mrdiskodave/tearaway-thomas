package com.nney.tt;

import java.util.Iterator;
import java.util.Random;

import org.lwjgl.opengl.GL11;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.ArrowAlien;
import com.nney.tt.aliens.BearAlien;
import com.nney.tt.aliens.BigGemAlien;
import com.nney.tt.aliens.BirdAlien;
import com.nney.tt.aliens.ExitAlien;
import com.nney.tt.aliens.HugeGemAlien;
import com.nney.tt.aliens.LogLiftAlien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.PurpleGemAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.aliens.ShieldAlien;
import com.nney.tt.aliens.SpriteAlien;
import com.nney.tt.aliens.StarAlien;
import com.nney.tt.aliens.StopAlien;
import com.nney.tt.aliens.TeleportAlien;
import com.nney.tt.aliens.WingAlien;
import com.nney.tt.aliens.WobbleGemAlien;
import com.nney.tt.aliens.YellowGemAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsDefPool;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.LineInfo;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class World implements AlienServices {

	// lift
//	private static final String CTC_WORLD = "w";
//	private static final int CTC_MAP = 9;

	// ladders & ice
	// private static final String CTC_WORLD = "i";
	// private static final int CTC_MAP = 0;

	 private static final String CTC_WORLD = "g";
	 private static final int CTC_MAP = 0;

	/**
	 * Compile time configuration: play in level containing only the map.
	 */
	private static final boolean CTC_TUMBLE_WEEDS = false;

	/**
	 * Compile time configuration: the screen follows the player <b>exactly</b>.
	 */
	private static final boolean CTC_HARD_SCROLLING = false;

	/**
	 * Compile time configuration: See the block masks (that determine ground or
	 * sky) rather than the block graphics.
	 */
	private static final boolean CTC_SEE_MASKS = false;

	private BlocksHolder blocksHolder;

	final public Random rnd = new Random(5);
	public MyFont debugFont;
	public MyFont font;

	public Coord screen = new Coord();
	public MasksHolder maskHolder;
	public Player player;

	public GameMap gameMap;
	public Box mapBounds;
	private AlienTracker alienTracker = new AlienTracker();

	public int frameNumber;

	private Sprite ttSprite;

	private Coord ttPos;

	private int score = 0;
	private int oldScore = -1;

	private PrerenderedText scoreHeadingText;

	private PrerenderedText scoreText;

	private int gemCounter;

	public WorldInformation wi;

	private GlTexture horizon;

	private AlienInfoMap alienInfoMap;
	private AnimsPool animsPool;
	private int teleAttempt;
	private int chosenBlock;
	private final Joystick joystick;
	private final Keyboard keyboard;
	private final Pointer mouse;
	private boolean mapper;

	public World(Joystick joystick, Keyboard keyboard, Pointer mouse) {
		this.joystick = joystick;
		this.keyboard = keyboard;
		this.mouse = mouse;

		AlienInfoMap aim = new AlienInfoMap();
		aim.add(new AlienInfo(2, "0ygem", YellowGemAlien.class));
		aim.add(new AlienInfo(3, "0pgem", PurpleGemAlien.class));
		aim.add(new AlienInfo(4, "0exit", ExitAlien.class));
		aim.add(new AlienInfo(5, "0shld", ShieldAlien.class));
		aim.add(new AlienInfo(6, "0bgem", BigGemAlien.class));
		aim.add(new AlienInfo(8, "0arru", ArrowAlien.class));
		aim.add(new AlienInfo(9, "0arrd", ArrowAlien.class));
		aim.add(new AlienInfo(10, "0arrl", ArrowAlien.class));
		aim.add(new AlienInfo(11, "0arrr", ArrowAlien.class));
		aim.add(new AlienInfo(12, "0tele", TeleportAlien.class));
		aim.add(new AlienInfo(14, "0wing", WingAlien.class));
		aim.add(new AlienInfo(15, "0spl1", SpriteAlien.class)); // special 1
		aim.add(new AlienInfo(16, "0spl2", SpriteAlien.class)); // special 2
		aim.add(new AlienInfo(17, "0spl3", SpriteAlien.class)); // special 3
		aim.add(new AlienInfo(18, "0cld0", SpriteAlien.class));
		aim.add(new AlienInfo(19, "0cld1", SpriteAlien.class));
		aim.add(new AlienInfo(20, "0cld2", SpriteAlien.class));
		// ail.add(new AlienInfo(34, null, ScoreGivingAlien.class));
		aim.add(new AlienInfo(42, "gpic2", SpriteAlien.class));
		aim.add(new AlienInfo(45, "gtrch", SpriteAlien.class));
		aim.add(new AlienInfo(65, "wfce0", SpriteAlien.class));
		aim.add(new AlienInfo(66, "wfce1", SpriteAlien.class));
		aim.add(new AlienInfo(67, "wfce2", SpriteAlien.class));
		aim.add(new AlienInfo(68, "wflr0", SpriteAlien.class));
		aim.add(new AlienInfo(69, "wflr1", SpriteAlien.class));
		aim.add(new AlienInfo(70, "wtrk0", SpriteAlien.class));
		aim.add(new AlienInfo(71, "wtrk1", SpriteAlien.class));
		aim.add(new AlienInfo(72, "wlog0", LogLiftAlien.class));
		aim.add(new AlienInfo(75, "wbird", BirdAlien.class));
		aim.add(new AlienInfo(76, "wbear", BearAlien.class));
		aim.add(new AlienInfo(86, "0hgem", HugeGemAlien.class));
		aim.add(new AlienInfo(93, "wfnsh", SpriteAlien.class));
		aim.add(new AlienInfo(95, "0star", StarAlien.class));
		aim.add(new AlienInfo(13, "0stop", StopAlien.class));
		aim.add(new AlienInfo(-1, "0scor", ScoreNoticeAlien.class));
		aim.add(new AlienInfo(-1, "0magc", MagicDustAlien.class));

		if (CTC_TUMBLE_WEEDS) {
			aim.clear();
		}

		alienInfoMap = aim;
		
		initFonts();
		init();
	}

	private void initFonts() {
		debugFont = new MyFont(OpenableTools.mustLoad(TTResource.font("topaz")), 8, 8, false,
				MyFont.characterRangeHelper(0, 128));

		font = new MyFont(OpenableTools.mustLoad(TTResource.font("font2")), 16, 11, true,
				"abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()' ");
	}

	// ---------------------------------------------------------------------------
	// MOSTLY SERVICES FOR THE ALIEN IMPLEMENTATIONS TO CALL

	@Override
	public int randomness(int n) {
		return rnd.nextInt(n);
	}

	private int getBlock(Coord c) {
		return gameMap.getBlock(c.x / 16, c.y / 16);
	}

	@Override
	public boolean inTheGround(Coord c) {
		int block = getBlock(c);
		return maskHolder.inTheGround(block, c.x & 15, c.y & 15);
	}

	/**
	 * What is there?
	 * 
	 * @param where
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

	private static Coord screenDest(Coord c) {
		return c.copyAndMove(-Main.SCREEN_WIDTH / 2, -Main.SCREEN_HEIGHT * 11 / 16);
	}

	private void limitScreenPosition() {
		screen.x = limit(screen.x, mapBounds.left, (mapBounds.right+1) - Main.SCREEN_WIDTH);
		screen.y = limit(screen.y, mapBounds.top, (mapBounds.bottom+1)- Main.SCREEN_HEIGHT);
	}

	private static int scrollOrd(int current, int dest) {
		current += shrinkDelta(dest - current);
		return current;
	}

	/**
	 * Scroll the screen gently towards the given position.
	 */
	@Override
	public void scrollScreenTo(Coord c) {
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
	public void drawDebugText(Coord c, final String text) {
		final Coord p = c.copy();
		p.sub(screen);
		drawAbsoluteDebugText(p, text);
	}

	private void drawAbsoluteDebugText(final Coord p, final String text) {
		debugFont.draw(p.x, p.y, 0x0000ff, 0, text);
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
		Box m = new Box(mapBounds);
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
	public boolean collideBoxWithPlayer(Coord alienPos, Box box) {
		int diffX = player.c.x - alienPos.x;
		int diffY = player.c.y - alienPos.y;

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

	private void addNewAlien(Alien alien) {
		alienInfoMap.connectAnims(alien, animsPool);
		alien.srv = this;
		alien.init();
		alienTracker.delayedAdd(alien);
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

	private void updateList(Iterator<Alien> alienIterator, Box screenBox) {
		for (; alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			alien.freezeBounds = null;
			alien.update();
			if (alien.remove || alienTracker.perhapsFreeze(alien, screenBox)) {
				alienIterator.remove();
			}
		}
	}

	private void updateAliens() {
		// add fresh aliens
		Box screenBox = Box.fromTopLeftAndSize(screen, Main.SCREEN_WIDTH, Main.SCREEN_HEIGHT);

		alienTracker.begin(screenBox);

		updateList(alienTracker.getBackgroundIterator(), screenBox);
		player.draw();
		updateList(alienTracker.getForegroundIterator(), screenBox);

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
		// "I am clear about the limits this imposes".
		//
	}

	private void updateScore() {
		if (score != oldScore) {
			scoreHeadingText = font.preDraw(0xffffff00, 0, "score");
			scoreText = font.preDraw(0xffffffff, 0, String.format("%08d", score));
		}
		scoreHeadingText.draw((Main.SCREEN_WIDTH - scoreHeadingText.getWidth()) / 2, 6);
		scoreText.draw((Main.SCREEN_WIDTH - scoreText.getWidth()) / 2, 6 + 14);
	}
	
	private int computeScrInBlocks(int blockSrcY, int scrSize, int mapSize) {
		int scrInBlocks = TTMath.roundUpDiv(scrSize, Main.BLOCK_SIZE);
		int mapInBlocks = mapSize/Main.BLOCK_SIZE;
		if (blockSrcY+scrInBlocks < mapInBlocks) {
			scrInBlocks++;
		}
		return scrInBlocks;
	}

	private void drawTheMap() {
		int blockSrcY = screen.y / Main.BLOCK_SIZE;
		int scrHeightInBlocks = computeScrInBlocks(blockSrcY, Main.SCREEN_HEIGHT, mapBounds.bottom+1);
		int blockSrcX = screen.x / Main.BLOCK_SIZE;
		int scrWidthInBlocks = computeScrInBlocks(blockSrcX, Main.SCREEN_WIDTH, mapBounds.right+1);

		int[] blockRow = new int[scrWidthInBlocks];

		int pixelDestY = -(screen.y & Main.BLOCK_MASK);
		for (int loopY = 0; loopY < scrHeightInBlocks; loopY++) {
			int pixelDestX = -(screen.x & Main.BLOCK_MASK);
			for (int loopX = 0; loopX < scrWidthInBlocks; loopX++) {
				blockRow[loopX] = gameMap.getBlock(blockSrcX + loopX, blockSrcY);
			}
			blocksHolder.draw(blockRow, pixelDestX, pixelDestY);
			pixelDestY += Main.BLOCK_SIZE;
			blockSrcY++;
		}
	}


	private void drawTheHorizon() {
		horizon.stretchDraw(0, 0, Main.SCREEN_WIDTH, Main.SCREEN_HEIGHT, 0, 0, horizon.getWidth(), horizon.getHieght());
	}

	void updateEverything() {
		frameNumber++;
		GlTools.configureFor2dBobs();

		if (mapper) {
			drawTheHorizon();
			drawTheMap();

			Coord mousePos = mouseCoord();
			{
				int x = mousePos.x/16;
				int y = mousePos.y/16;
				x*=16;
				y*=16;
				drawHollowRect(x-screen.x, y-screen.y, 16, 16, 0xff0000);

			}

			if (keyboard.isDown(Keyboard.KEY_B)) {
				blockChoosingMode();
			}
			else {
				switch (keyboard.justPressed()) {
				case Keyboard.KEY_TAB:
					player.resetTo(mouseCoord());
					mapper = false;
				break;
				case Keyboard.KEY_I:
				}
				if (mouse.testButton(Pointer.LEFT)) {
					Coord z = mouseCoord();
					gameMap.setBlock(z.x/16, z.y/16, chosenBlock);
				}

				scrollScreenTo(mousePos);
			}
		}
		else {
			if (keyboard.justPressed()==Keyboard.KEY_TAB) {
				mapper = true;
			}
			player.move();
			if (CTC_HARD_SCROLLING) {
				snapScreenTo(player.c);
			}
			else {
				scrollScreenTo(player.c);
			}

			drawTheHorizon();
			drawTheMap();
			updateAliens();
			updateScore();
		}
	}

	private Coord mouseCoord() {
		return new Coord(mouse.getX()+screen.x, mouse.getY()+screen.y);
	}

	private void loadAlienIntoWorld(Alien alien) {
		alien.srv = this;
		if (alien instanceof WobbleGemAlien) {
			gemCounter++;
		}
		alien.init();
		alienTracker.delayedAdd(alien);
	}

	private void init() {
		horizon = new GlTexture(new SimpleImage(OpenableTools.mustLoad(TTResource.horizon(1))));
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_LINEAR);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_LINEAR);

		animsPool = new AnimsPool(new AnimsDefPool());
		alienInfoMap.doPreLoad(animsPool);

		player = new Player();
		player.srv = this;
		Anims playerAnims = animsPool.load("0tt");
		player.connectAnims(playerAnims);
		player.init();

		String worldName = CTC_WORLD;
		Openable blocksGfx = TTResource.blocks(worldName);
		Openable masksGfx = TTResource.blockMask(worldName);
		wi = WorldInformation.load(worldName);
		blocksHolder = new BlocksHolder(16, 8, CTC_SEE_MASKS ? masksGfx : blocksGfx, wi.invisibleBlockHiding);
		maskHolder = new MasksHolder(16, masksGfx);

		Openable mapOpenable = TTResource.map(worldName, CTC_MAP);

		PersistedMap pm = new PersistedMap();
		pm.loadLegacy(animsPool, alienInfoMap, mapOpenable);
		for (Alien a : pm.aliens) {
			loadAlienIntoWorld(a);
		}
		mapBounds = pm.mapBounds;
		player.c.x = pm.playerX;
		player.c.y = pm.playerY;
		player.goLeft = pm.playerGoLeft;
		gameMap = pm.gameMap;

		// player.c.x = 1980;
		// player.c.y = 1020;
		snapScreenTo(player.c);

		gameMap.applyShuffle(wi.blockRandomisationTable);
	}

	@Override
	public void teleportTo(Coord destination) {
		// if we didn't try teleporting last frame
		if (teleAttempt + 1 != frameNumber) {
			// do it
			player.c = destination.copy();
			snapScreenTo(destination);
		}
		teleAttempt = frameNumber;
		// (this stops us vibrating between two teleports)
	}

	void drawSolidRect(int x, int y, int w, int h, int col) {
		GlTools.reset();
		GlTools.selectColor(col);
		GL11.glRecti(x, y, x + w, y + h);
		GlTools.configureFor2dBobs();
	}

	private void drawSight(int x, int y, int i, int col) {
		drawSolidRect(x - i, y, i * 2, 1, col);
		drawSolidRect(x, y - i, 1, i * 2, col);
	}

	private void drawHollowRect(int x, int y, int w, int h, int c) {
		drawSolidRect(x, y, w, 1, c);
		drawSolidRect(x, y, 1, h, c);
		drawSolidRect(x + w - 1, y, 1, h, c);
		drawSolidRect(x, y + h - 1, w, 1, c);
	}

	public void blockChoosingMode() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);

		int mx = mouse.getX();
		int my = mouse.getY();
//		System.out.println(String.format("%d,%d", mx, my));
//		drawSight(mx, my, 20, 0xff0000);
		
		int blocksPerLine = 20;
		
		int blockCount = blocksHolder.getBlockCount();
		int lines = (blockCount+(blocksPerLine-1))/blocksPerLine;
		lines*=16;
		int protrusion = Math.max(lines-Main.SCREEN_HEIGHT, 0);
		int movement = 0;
		if (protrusion!=0) {
			int mid = 64;
			int big = Main.SCREEN_HEIGHT-1-mid-mid;
			int z = Math.min(Math.max(0, my-mid), big);
			movement = (protrusion*z)/big;
		}
		
		GlTools.configureFor2dBobs();
		int[] z = new int[1];
		int hoverBlock = -1;
		for (int b = 0; b < blockCount; b++) {
			int x = b % blocksPerLine;
			int y = b / blocksPerLine;
			x *= 16;
			y *= 16;
			y -= movement;
			z[0] = b;
			blocksHolder.draw(z, x, y);
			if (chosenBlock == b) {
				drawHollowRect(x, y, 16, 16, 0xff0000);
				debugFont.draw(blocksPerLine*16, y, 0xff0000, 0, String.format("%4d", chosenBlock));
			}
			if (my>=y && my<=y+15 && mx>=x && mx<=x+15) {
				hoverBlock = b;
				if (hoverBlock==chosenBlock) {
					drawHollowRect(x+1, y+1, 14, 14, 0xffff00);
				}
				else {
					drawHollowRect(x, y, 16, 16, 0xffff00);
				}
				debugFont.draw(blocksPerLine*16+8*4, y, 0xffff00, 0, String.format("%4d", hoverBlock));
			}
		}
		if (mouse.testButton(Pointer.LEFT) && hoverBlock>=0) {
			chosenBlock = hoverBlock;
		}
	}

}
