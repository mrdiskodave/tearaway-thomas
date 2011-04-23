package com.nney.tt;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.json.JsonException;
import com.nney.json.JsonValue;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.ArrowAlien;
import com.nney.tt.aliens.BearAlien;
import com.nney.tt.aliens.BirdAlien;
import com.nney.tt.aliens.GemAlien;
import com.nney.tt.aliens.LiftAlien;
import com.nney.tt.aliens.ScoreAlien;
import com.nney.tt.aliens.ShieldAlien;
import com.nney.tt.aliens.SpriteAlien;
import com.nney.tt.aliens.StopAlien;
import com.nney.tt.aliens.TextAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.map.BlockRandomisationTable;
import com.nney.tt.map.BlockSpecifications;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.SpriteDefPool;
import com.nney.tt.sprites.SpriteSet;
import com.nney.tt.sprites.SpriteSetPool;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;
import com.nney.utils.StringIO;

public class Main {
	/**
	 * Compile time configuration: play in level containing only the map.
	 */
	private static final boolean CTC_TUMBLE_WEEDS = true;

	/**
	 * Compile time configuration: 
	 */
	private static final boolean CTC_HARD_SCROLLING = false;

	private static final int ZOOM = 2;

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	private static final boolean CTC_SEE_MASKS = false;

	private BlocksHolder blocksHolder;

	private World world = new World();

	private boolean closing;

	private FpsReporter fpsRep;

	public HashSet<Integer> keys = new HashSet<Integer>();

	private MyFont font;

	private MyFont debugFont;

	private int frameNumber;

	private List<Alien> backgroundAlienList = new ArrayList<Alien>();
	private List<Alien> foregroundAlienList = new ArrayList<Alien>();

	private Player player;

	private GlTexture horizon;

	private SpriteSet pss;

	private PrerenderedText scoreText;

	private PrerenderedText gemsText;

	private PrerenderedText timeText;

	private void initLwjgl() {
		try {
			Display.setDisplayMode(new DisplayMode(SCREEN_WIDTH * ZOOM, SCREEN_HEIGHT * ZOOM));
			Display.create();
			Display.setVSyncEnabled(true);
			Keyboard.create();
		}
		catch (LWJGLException e) {
			throw new RuntimeException(e);
		}
	}

	private void readJoystick() {
		int x = 0;
		if (testKey(Keyboard.KEY_Q)) {
			x |= Joystick.UP;
		}
		if (testKey(Keyboard.KEY_A)) {
			x |= Joystick.DOWN;
		}
		if (testKey(Keyboard.KEY_O)) {
			x |= Joystick.LEFT;
		}
		if (testKey(Keyboard.KEY_P)) {
			x |= Joystick.RIGHT;
		}
		if (testKey(Keyboard.KEY_SPACE)) {
			x |= Joystick.FIRE;
		}
		world.setJ(x);
	}

	private boolean testKey(int key) {
		return keys.contains(key);
	}

	private void initOpenGL() {
		GlTools.reset();

		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glClearColor(0.0f, 0.5f, 1.0f, 0.0f);

		GL11.glViewport(0, 0, SCREEN_WIDTH * ZOOM, SCREEN_HEIGHT * ZOOM);

		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
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

	private void init() {
		horizon = new GlTexture(new SimpleImage(OpenableTools.mustLoad(TTResource.horizon(1))));
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_LINEAR);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_LINEAR);

		List<AlienInfo> ail = new ArrayList<AlienInfo>();
		ail.add(new AlienInfo(2, "0ygem", GemAlien.class));
		ail.add(new AlienInfo(3, "0pgem", GemAlien.class));
		ail.add(new AlienInfo(5, "0shld", ShieldAlien.class));
		ail.add(new AlienInfo(8, "0arru", ArrowAlien.class));
		ail.add(new AlienInfo(9, "0arrd", ArrowAlien.class));
		ail.add(new AlienInfo(10, "0arrl", ArrowAlien.class));
		ail.add(new AlienInfo(11, "0arrr", ArrowAlien.class));
		ail.add(new AlienInfo(18, "0cld0", SpriteAlien.class));
		ail.add(new AlienInfo(19, "0cld1", SpriteAlien.class));
		ail.add(new AlienInfo(20, "0cld2", SpriteAlien.class));
		ail.add(new AlienInfo(34, null, ScoreAlien.class));
		ail.add(new AlienInfo(42, "gpic2", SpriteAlien.class));
		ail.add(new AlienInfo(45, "gtrch", SpriteAlien.class));
		ail.add(new AlienInfo(65, "wfce0", SpriteAlien.class));
		ail.add(new AlienInfo(66, "wfce1", SpriteAlien.class));
		ail.add(new AlienInfo(67, "wfce2", SpriteAlien.class));
		ail.add(new AlienInfo(68, "wflr0", SpriteAlien.class));
		ail.add(new AlienInfo(69, "wflr1", SpriteAlien.class));
		ail.add(new AlienInfo(70, "wtrk0", SpriteAlien.class));
		ail.add(new AlienInfo(71, "wtrk1", SpriteAlien.class));
		ail.add(new AlienInfo(72, "wlog0", LiftAlien.class));
		ail.add(new AlienInfo(75, "wbird", BirdAlien.class));
		ail.add(new AlienInfo(76, "wbear", BearAlien.class));
		ail.add(new AlienInfo(93, "wfnsh", SpriteAlien.class));

		if (CTC_TUMBLE_WEEDS) {
			ail.clear();
		}
		ail.add(new AlienInfo(13, "0stop", StopAlien.class));

		Map<Integer, AlienInfo> aim = new HashMap<Integer, AlienInfo>();
		for (AlienInfo alienInfo : ail) {
			aim.put(alienInfo.id, alienInfo);
		}

		SpriteDefPool sdp = new SpriteDefPool();
		SpriteSetPool spriteSetPool = new SpriteSetPool(sdp);

		player = new Player();
		player.srv = world;
		SpriteSet playerSpriteSet = spriteSetPool.load("0tt");
		pss = playerSpriteSet;
		player.connectSpriteSet(playerSpriteSet);
		player.init();

		String worldName = "w";
		Openable blocksGfx = TTResource.blocks(worldName);
		Openable masksGfx = TTResource.blockMask(worldName);
		blocksHolder = new BlocksHolder(16, 8, CTC_SEE_MASKS ? masksGfx : blocksGfx);
		MasksHolder maskHolder = new MasksHolder(16, masksGfx);

		BlockRandomisationTable rt;
		BlockSpecifications bs;

		try {
			String t = StringIO.loadText(TTResource.blockDef(worldName), null);
			JsonValue v = JsonValue.parse(t);
			rt = new BlockRandomisationTable(v.requireField("rt"));
			bs = new BlockSpecifications(v.requireField("spec"));
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}

		try {
			Box mapBounds = null;
			InputStream i = TTResource.map("w", 5).open();
			DataInputStream di = new DataInputStream(i);

			// get the game map off the front of the stream
			GameMap gameMap = new GameMap(di);
			gameMap.applyRt(rt);

			// read the other things
			for (;;) {
				String id = readChunkId(di);
				if (id.equals("set2")) {
					player.c.x = di.readShort();
					player.c.y = di.readShort();
					player.goLeft = di.readByte() != 0;

					di.readByte(); // blkset
					di.readByte(); // specjsr1
					di.readByte(); // specjsr2
					di.readByte(); // specjsr3
					int minx = di.readByte() & 0xff;
					int maxx = di.readByte() & 0xff;
					int miny = di.readByte() & 0xff;
					int maxy = di.readByte() & 0xff;
					minx *= 16;
					maxx *= 16;
					maxx += 15;
					miny *= 16;
					maxy *= 16;
					maxy += 15;
					mapBounds = new Box(minx, miny, maxx, maxy);
					// mapBounds = new Box(0, 0, Integer.MAX_VALUE,
					// Integer.MAX_VALUE);

					for (int r = 0x30 - 5 - 4 - 4; r-- > 0;) {
						di.readByte();
					}
				}
				else if (id.equals("obj2")) {
					int objectCnt = 0;
					for (;;) {
						int x = di.readShort();
						int y = di.readShort();
						if (x < 0) break;
						int type = di.readByte();
						byte[] rest = new byte[21];
						for (int o = 0; o < 21; o++) {
							rest[o] = di.readByte();
						}
						objectCnt++;

						try {
							AlienInfo alienInfo = aim.get(type);
							if (alienInfo != null) {
								// aim.remove(type); // ONCE!
								Alien alien = alienInfo.instantiate();
								alien.srv = world;
								if (alienInfo.spriteSetName != null) {
									SpriteSet ss = spriteSetPool.load(alienInfo.spriteSetName);
									alien.connectSpriteSet(ss);
								}
								if (type == 2 || type == 3) {
									// this is what gem_render -> bob_gem does
									x += 8;
								}
								alien.c.x = x;
								alien.c.y = y;
								alien.srcData = rest;
								alien.load();

								if (alien instanceof LoadsFromSpriteDef) {
									((LoadsFromSpriteDef) alien).load(sdp.load(alienInfo.spriteSetName));
								}

								alien.init();
								saveAlien(alien);
							}
							else {
								TextAlien alien = new TextAlien();
								alien.srv = world;
								alien.setText(String.format("%d", type));
								alien.c.x = x;
								alien.c.y = y;
								alien.init();
								saveAlien(alien);
							}
						}
						catch (InstantiationException e) {
							throw new RuntimeException(e);
						}
						catch (IllegalAccessException e) {
							throw new RuntimeException(e);
						}
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

			debugFont = new MyFont(OpenableTools.mustLoad(TTResource.font("topaz")), 8, 8, false,
					MyFont.characterRangeHelper(0, 128));

			font = new MyFont(OpenableTools.mustLoad(TTResource.font("font2")), 16, 11, true,
					"abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()' ");

			scoreText = font.preDraw(0xffffff00, 0, "score");
			gemsText = font.preDraw(0xffffff00, 0, "gems");
			timeText = font.preDraw(0xffffff00, 0, "time");

			// TODO: ctor??
			world.gameMap = gameMap;
			world.maskHolder = maskHolder;
			world.bs = bs;
			world.debugFont = debugFont;
			world.font = font;
			world.player = player;
			world.mapBounds = mapBounds;
			
			player.c.x = 1980;
			player.c.y = 1020;
			world.snapScreenTo(player.c);

			// bear.c.x = 455;
			// bear.c.y = 818 + 50;

		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void saveAlien(Alien alien) {
		List<Alien> alienList = alien.infront ? foregroundAlienList : backgroundAlienList;
		alienList.add(alien);
	}

	private void drawTheMap() {
		final int BLOCK_SIZE = 16;
		final int BLOCK_MASK = BLOCK_SIZE - 1;
		final int SCREEN_HEIGHT_IN_BLOCKS = (SCREEN_HEIGHT + BLOCK_MASK) / BLOCK_SIZE + 1;
		final int SCREEN_WIDTH_IN_BLOCKS = (SCREEN_WIDTH + BLOCK_MASK) / BLOCK_SIZE + 1;

		int[] blockrow = new int[SCREEN_WIDTH_IN_BLOCKS];

		int screenX = world.screen.x;
		int screenY = world.screen.y;
		int pixelDestY = -(screenY & BLOCK_MASK);
		int blockSrcY = screenY / BLOCK_SIZE;
		for (int loopY = 0; loopY < SCREEN_HEIGHT_IN_BLOCKS; loopY++) {
			int pixelDestX = -(screenX & BLOCK_MASK);
			int blockSrcX = screenX / BLOCK_SIZE;
			for (int loopX = 0; loopX < SCREEN_WIDTH_IN_BLOCKS; loopX++) {
				blockrow[loopX] = world.gameMap.getBlock(blockSrcX + loopX, blockSrcY);
			}
			blocksHolder.draw(blockrow, pixelDestX, pixelDestY);
			pixelDestY += BLOCK_SIZE;
			blockSrcY++;
		}
	}

	private void drawEverything() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);

		GlTools.configureFor2dBobs();

		readJoystick();
		player.move();

		if (CTC_HARD_SCROLLING) {
			world.snapScreenTo(player.c);
		}
		else {
			world.scrollScreenTo(player.c);
		}


		// for (int x=0; x<15; x++) {
		// pss.find(0).frames[0].draw(50+40*x,50+40*x,false);
		// }

		//
		// draw everything
		//
		
		drawTheHorizon();
		drawTheMap();

		updateAliens(backgroundAlienList);
		player.draw();
		updateAliens(foregroundAlienList);

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
		// For now, it'll work how it used to. For the first time I can say "I am
		// clear about the limits this imposes".
		//

		font.draw(5, 50, 0x00ff00, 0, String.format("frm#%06d", frameNumber));

		scoreText.draw((SCREEN_WIDTH - scoreText.getWidth()) / 2, 5);
	}

	private void drawTheHorizon() {
		horizon.stretchDraw(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 0, horizon.getWidth(), horizon.getHieght());
	}

	private void updateAliens(List<Alien> al) {
		for (Iterator<Alien> ai = al.iterator(); ai.hasNext();) {
			Alien alien = ai.next();
			alien.update();
			if (alien.remove) {
				ai.remove();
			}
		}
	}

	private void handleKeyboard() {
		while (Keyboard.next()) {
			int key = Keyboard.getEventKey();
			boolean down = Keyboard.getEventKeyState();
			if (down) {
				keys.add(key);
			}
			else {
				keys.remove(key);
			}
			if (key == Keyboard.KEY_F12 && down) {
				Mouse.setGrabbed(!Mouse.isGrabbed());
			}
		}
	}

	private void run() {
		initLwjgl();
		initOpenGL();
		init();

		int requestedFps = 50;
		fpsRep = new FpsReporter(200);
		while (!closing) {
			Display.sync(requestedFps);

			frameNumber++;
			world.frameNumber = frameNumber;

			handleKeyboard();

			drawEverything();

			Display.update();
			if (Display.isCloseRequested()) {
				closing = true;
			}

			fpsRep.reportFps();
			Thread.yield();
		}
		Display.destroy();
	}

	public static void main(String[] argv) {
		Main textureExample = new Main();
		textureExample.run();
	}
}
