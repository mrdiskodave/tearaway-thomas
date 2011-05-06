package com.nney.tt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Random;

import org.lwjgl.opengl.GL11;

import com.nney.tt.aliens.AbstractGemAlien;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.ArrowAlien;
import com.nney.tt.aliens.BearAlien;
import com.nney.tt.aliens.BirdAlien;
import com.nney.tt.aliens.ExitAlien;
import com.nney.tt.aliens.LiftAlien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.PurpleGemAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.aliens.ShieldAlien;
import com.nney.tt.aliens.SpriteAlien;
import com.nney.tt.aliens.StarAlien;
import com.nney.tt.aliens.StopAlien;
import com.nney.tt.aliens.TextAlien;
import com.nney.tt.aliens.WingAlien;
import com.nney.tt.aliens.YellowGemAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;
import com.nney.tt.gfx.SimpleImage;
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

public class World implements AlienServices, Joystick {

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
	 * Compile time configuration:
	 */
	private static final boolean CTC_HARD_SCROLLING = false;

	private static final boolean CTC_SEE_MASKS = false;

	private BlocksHolder blocksHolder;

	final public Random rnd = new Random(5);
	public MyFont debugFont;
	public MyFont font;

	public Coord screen = new Coord();
	public GameMap gameMap;
	public MasksHolder maskHolder;
	public Player player;

	public Box mapBounds;

	public int frameNumber;

	private Sprite ttSprite;

	private Coord ttPos;

	private int joystick;

	private int joystickAA;

	private int score = 0;
	private int oldScore = -1;

	private PrerenderedText scoreHeadingText;

	private PrerenderedText scoreText;

	private int gemCounter;

	public WorldInformation wi;

	private GlTexture horizon;

	private AlienTracker alienTracker = new AlienTracker();
	private AlienInfoMap alienInfoMap;
	private AnimsPool animsPool;

	public World() {
		AlienInfoMap aim = new AlienInfoMap();
		aim.add(new AlienInfo(2, "0ygem", YellowGemAlien.class));
		aim.add(new AlienInfo(3, "0pgem", PurpleGemAlien.class));
		aim.add(new AlienInfo(4, "0exit", ExitAlien.class));
		aim.add(new AlienInfo(5, "0shld", ShieldAlien.class));
		aim.add(new AlienInfo(8, "0arru", ArrowAlien.class));
		aim.add(new AlienInfo(9, "0arrd", ArrowAlien.class));
		aim.add(new AlienInfo(10, "0arrl", ArrowAlien.class));
		aim.add(new AlienInfo(11, "0arrr", ArrowAlien.class));
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
		aim.add(new AlienInfo(72, "wlog0", LiftAlien.class));
		aim.add(new AlienInfo(75, "wbird", BirdAlien.class));
		aim.add(new AlienInfo(76, "wbear", BearAlien.class));
		aim.add(new AlienInfo(93, "wfnsh", SpriteAlien.class));
		aim.add(new AlienInfo(95, "0star", StarAlien.class));
		aim.add(new AlienInfo(13, "0stop", StopAlien.class));
		aim.add(new AlienInfo(-1, "0scor", ScoreNoticeAlien.class));
		aim.add(new AlienInfo(-1, "0magc", MagicDustAlien.class));

		if (CTC_TUMBLE_WEEDS) {
			aim.clear();
		}

		alienInfoMap = aim;
	}

	void init2() {
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
//		if (answer) {
//			System.out.println(String.format("Is %s is %s", getBlock(c), name));
//		}
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
	public void removeOneGem(int score, Coord noticeLocation) {
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
		screen.x = limit(screen.x, mapBounds.left, mapBounds.right - Main.SCREEN_WIDTH);
		screen.y = limit(screen.y, mapBounds.top, mapBounds.bottom - Main.SCREEN_HEIGHT);
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
		return this;
	}

	@Override
	public boolean test(int mask) {
		return (mask & joystick) != 0;
	}

	@Override
	public boolean testAntiAutofire(int mask) {
		return (mask & joystickAA) != 0;
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
		// placement of the screen until quite late (which makes pixels perfect
		// Alien freezing and defrosting impossible). That's a big voyage into
		// new territory for little gain.
		//
		// For now, it'll work how it used to. For the first time I can say "I
		// am clear about the limits this imposes".
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

	private void drawTheMap() {
		final int BLOCK_SIZE = 16;
		final int BLOCK_MASK = BLOCK_SIZE - 1;
		final int SCREEN_HEIGHT_IN_BLOCKS = (Main.SCREEN_HEIGHT + BLOCK_MASK) / BLOCK_SIZE + 1;
		final int SCREEN_WIDTH_IN_BLOCKS = (Main.SCREEN_WIDTH + BLOCK_MASK) / BLOCK_SIZE + 1;

		int[] blockrow = new int[SCREEN_WIDTH_IN_BLOCKS];

		int screenX = screen.x;
		int screenY = screen.y;
		int pixelDestY = -(screenY & BLOCK_MASK);
		int blockSrcY = screenY / BLOCK_SIZE;
		for (int loopY = 0; loopY < SCREEN_HEIGHT_IN_BLOCKS; loopY++) {
			int pixelDestX = -(screenX & BLOCK_MASK);
			int blockSrcX = screenX / BLOCK_SIZE;
			for (int loopX = 0; loopX < SCREEN_WIDTH_IN_BLOCKS; loopX++) {
				blockrow[loopX] = gameMap.getBlock(blockSrcX + loopX, blockSrcY);
			}
			blocksHolder.draw(blockrow, pixelDestX, pixelDestY);
			pixelDestY += BLOCK_SIZE;
			blockSrcY++;
		}
	}

	private void drawTheHorizon() {
		horizon.stretchDraw(0, 0, Main.SCREEN_WIDTH, Main.SCREEN_HEIGHT, 0, 0, horizon.getWidth(), horizon.getHieght());
	}

	private void setJoystickPosition(int next) {
		int last = joystick;
		joystick = next;
		joystickAA = next & ~last;
	}

	void updateEverything(int j) {
		frameNumber++;

		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);

		GlTools.configureFor2dBobs();

		setJoystickPosition(j);
		player.move();

		if (CTC_HARD_SCROLLING) {
			snapScreenTo(player.c);
		}
		else {
			scrollScreenTo(player.c);
		}

		// for (int x=0; x<15; x++) {
		// pss.find(0).frames[0].draw(50+40*x,50+40*x,false);
		// }

		//
		// draw everything
		//

		drawTheHorizon();
		drawTheMap();

		// font.draw(5, 50, 0x00ff00, 0, String.format("frm#%06d",
		// frameNumber));
		updateAliens();

		updateScore();
	}

	// ---------------------------------------------------------------------------
	// MAP LOADING

	private void loadAlienIntoWorld(Alien alien) {
		if (alien instanceof AbstractGemAlien) {
			gemCounter++;
		}
		alien.init();
		alienTracker.delayedAdd(alien);
	}

	private String readChunkId(DataInputStream di) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int r = 4; r-- > 0;) {
			sb.append((char) di.readByte());
		}
		String id = sb.toString();
		System.out.println("Got chunk: >" + id + "<");
		return id;
	}

	private void loadRawSettings(byte[] rawSettings) throws IOException {
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rawSettings));
		player.c.x = dis.readShort();
		player.c.y = dis.readShort();
		player.goLeft = dis.readByte() != 0;
	
		dis.readByte(); // blkset
		dis.readByte(); // specjsr1
		dis.readByte(); // specjsr2
		dis.readByte(); // specjsr3
		int minx = dis.readByte() & 0xff;
		int maxx = dis.readByte() & 0xff;
		int miny = dis.readByte() & 0xff;
		int maxy = dis.readByte() & 0xff;
		minx *= 16;
		maxx *= 16;
		maxx += 15;
		miny *= 16;
		maxy *= 16;
		maxy += 15;
		mapBounds = new Box(minx, miny, maxx, maxy);
	}

	private void loadLegacyAlienIntoWorld(int x, int y, int type, byte[] rest) {
		try {
			AlienInfo alienInfo = alienInfoMap.getByType(type);
			if (alienInfo != null) {
				// aim.remove(type); // ONCE!
	
				Alien alien = alienInfo.instantiate();
				alien.srv = this;
				if (alienInfo.animsName != null) {
					Anims anims = animsPool.load(alienInfo.animsName);
					alien.connectAnims(anims);
				}
				if (type == 2 || type == 3) {
					// this is what gem_render -> bob_gem does
					x += 8;
				}
				alien.c.x = x;
				alien.c.y = y;
				alien.srcData = rest;
				alien.load();
	
				// if (alien instanceof LoadsFromSpriteDef) {
				// ((LoadsFromSpriteDef)
				// alien).load(adp.load(alienInfo.animsName));
				// }
	
				loadAlienIntoWorld(alien);
			}
			else {
				TextAlien alien = new TextAlien();
				alien.srv = this;
				alien.setText(String.format("%d", type));
				alien.c.x = x;
				alien.c.y = y;
				loadAlienIntoWorld(alien);
			}
		}
		catch (InstantiationException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private void loadLegacyMap(Openable mapOpenable) {
		try {
			InputStream i = mapOpenable.open();
			DataInputStream di = new DataInputStream(i);
			// get the game map off the front of the stream
			gameMap = new GameMap(di);
	
	
			// read the other things
			for (;;) {
				String id = readChunkId(di);
				if (id.equals("set2")) {
					byte[] rawSettings = new byte[0x30];
					di.readFully(rawSettings);
					loadRawSettings(rawSettings);
				}
				else if (id.equals("obj2")) {
					for (;;) {
						int x = di.readShort();
						int y = di.readShort();
						if (x < 0) break;
						int type = di.readByte();
						byte[] rest = new byte[21];
						di.readFully(rest);
	
						loadLegacyAlienIntoWorld(x, y, type, rest);
					}
				}
				else if (id.equals("pal2")) {
					while (di.readShort() != -1) {
					}
				}
				else if (id.equals("end!")) {
					break;
				}
				else {
					throw new RuntimeException("Unknown chunk: " + id);
				}
			}
	
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	void init() {
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
		loadLegacyMap(mapOpenable);
		
		// player.c.x = 1980;
		// player.c.y = 1020;
		snapScreenTo(player.c);
		
		gameMap.applyRt(wi.blockRandomisationTable);
	}

	
}
