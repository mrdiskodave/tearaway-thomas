package com.nney.tt;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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
import com.nney.tt.aliens.ScoreAlien;
import com.nney.tt.aliens.SpriteAlien;
import com.nney.tt.aliens.TextAlien;
import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.map.BlockRandomisationTable;
import com.nney.tt.map.BlockSpecifications;
import com.nney.tt.map.BlocksHolder;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.SpriteDefPool;
import com.nney.tt.sprites.SpriteSet;
import com.nney.tt.sprites.SpriteSetPool;
import com.nney.utils.OpenableTools;
import com.nney.utils.StringIO;

public class Main {
	private static final int ZOOM = 2;

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	private BlocksHolder blocksHolder;

	private World world = new World();

	private boolean closing;

	private FpsReporter fpsRep;

	public HashSet<Integer> keys = new HashSet<Integer>();

	private MyFont font;

	private MyFont debugFont;

	private int frameNumber;

	private List<Alien> alienList = new ArrayList<Alien>();

	private Player player;

	private GlTexture horizon;

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
		ail.add(new AlienInfo(76, "wbear", BearAlien.class));
		ail.add(new AlienInfo(75, "wbird", BirdAlien.class));
		ail.add(new AlienInfo(18, "0cld0", SpriteAlien.class));
		ail.add(new AlienInfo(19, "0cld1", SpriteAlien.class));
		ail.add(new AlienInfo(20, "0cld2", SpriteAlien.class));
		ail.add(new AlienInfo(42, "gpic2", SpriteAlien.class));
		ail.add(new AlienInfo(45, "gtrch", SpriteAlien.class));
		ail.add(new AlienInfo(65, "wfce0", SpriteAlien.class));
		ail.add(new AlienInfo(66, "wfce1", SpriteAlien.class));
		ail.add(new AlienInfo(67, "wfce2", SpriteAlien.class));
		ail.add(new AlienInfo(70, "wtrk0", SpriteAlien.class));
		ail.add(new AlienInfo(71, "wtrk1", SpriteAlien.class));
		ail.add(new AlienInfo(93, "wfnsh", SpriteAlien.class));
		ail.add(new AlienInfo(68, "wflr0", SpriteAlien.class));
		ail.add(new AlienInfo(69, "wflr1", SpriteAlien.class));
		ail.add(new AlienInfo(8, "0arru", ArrowAlien.class));
		ail.add(new AlienInfo(9, "0arrd", ArrowAlien.class));
		ail.add(new AlienInfo(10, "0arrl", ArrowAlien.class));
		ail.add(new AlienInfo(11, "0arrr", ArrowAlien.class));
		ail.add(new AlienInfo(34, null, ScoreAlien.class));

		Map<Integer, AlienInfo> aim = new HashMap<Integer, AlienInfo>();
		for (AlienInfo alienInfo : ail) {
			aim.put(alienInfo.id, alienInfo);
		}

		SpriteDefPool sdp = new SpriteDefPool();
		SpriteSetPool spriteSetPool = new SpriteSetPool(sdp);

		player = new Player();
		player.connectSpriteSet(spriteSetPool.load("0tt"));
		player.init();

		String worldName = "w";
		blocksHolder = new BlocksHolder(16, 8, TTResource.blocks(worldName));

		MasksHolder maskHolder = new MasksHolder(16, TTResource.blockMask(worldName));

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
			InputStream i = TTResource.map("w", 0).open();
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
					for (int r = 0x30 - 5; r-- > 0;) {
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
								if (alienInfo.spriteSetName != null) {
									SpriteSet ss = spriteSetPool.load(alienInfo.spriteSetName);
									alien.connectSpriteSet(ss);
								}
								alien.c.x = x;
								alien.c.y = y;
								alien.srcData = rest;
								alien.load();

								if (alien instanceof LoadsFromSpriteDef) {
									((LoadsFromSpriteDef) alien).load(sdp.load(alienInfo.spriteSetName));
								}

								alien.init();
								alienList.add(alien);
							}
							else {
								TextAlien alien = new TextAlien();
								alien.setText(String.format("%d", type));
								alien.c.x = x;
								alien.c.y = y;
								alienList.add(alien);
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

			// TODO: ctor??
			world.screen.x = 970;
			world.screen.y = 864;
			world.gameMap = gameMap;
			world.maskHolder = maskHolder;
			world.bs = bs;
			world.keys = keys;
			world.debugFont = debugFont;
			world.font = font;
			world.player = player;

			// bear.c.x = 455;
			// bear.c.y = 818 + 50;

		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
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

		
		horizon.stretchDraw(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 0, horizon.getWidth(), horizon.getHieght());
		
		drawTheMap();
		for (Alien alien : alienList) {
			alien.draw(world);
		}
		player.draw(world);

		if (world.playerInFront) {
			world.runTheRenderQueue();
		}
		else {
			world.runTheRenderQueueWithLastItemFirst();
		}

		debugFont.draw(5, 50, 0x00ff00, 0, String.format("frm#%06d", frameNumber));
	}

	private void moveEverything() {
		player.move(world);
		for (Alien alien : alienList) {
			alien.move(world);
		}
		world.scrollTowards(player.c);
		frameNumber++;
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

			if (key == Keyboard.KEY_SPACE && down) {
				Mouse.setGrabbed(!Mouse.isGrabbed());
			}
		}
	}

	private void run() {
		initLwjgl();
		initOpenGL();
		init();

		int requested_fps = 50;
		fpsRep = new FpsReporter(200);
		while (!closing) {
			Display.sync(requested_fps);

			handleKeyboard();

			world.startFrame();
			moveEverything();
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