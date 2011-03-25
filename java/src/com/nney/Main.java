package com.nney;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class Main {
	private static final int ZOOM = 2;

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	private BlocksHolder blocksHolder;

	private World world = new World();

	private Bear bear;

	private boolean closing;

	private FpsReporter fpsRep;

	public HashSet<Integer> keys = new HashSet<Integer>();

	private MyFont myFont;

	private int frameNumber;
	
	private List<Alien> alienList = new ArrayList<Alien>();

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
		discoverDisplayDepth();
		GlTools.reset();

		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glClearColor(0.0f, 0.5f, 1.0f, 0.0f);

		GL11.glViewport(0, 0, SCREEN_WIDTH * ZOOM, SCREEN_HEIGHT * ZOOM);

		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}

	private void discoverDisplayDepth() {
		int r = GL11.glGetInteger(GL11.GL_RED_BITS);
		int g = GL11.glGetInteger(GL11.GL_GREEN_BITS);
		int b = GL11.glGetInteger(GL11.GL_BLUE_BITS);
		System.out.println("colour bits:");
		System.out.println(r);
		System.out.println(g);
		System.out.println(b);
	}

	private void initGfx() {
		FrameLoader frameLoader = new LargeImageFrameLoader() {
			@Override
			FileOpenable findData(SpriteName f) {
				// all that is missing is knowledge of how to find those large
				// frames!
				String filename = String.format(
						"C:\\Users\\david\\Desktop\\newdata\\bobs\\%s_%03d.png", f.name, f.number);
				return new FileOpenable(filename);
			}
		};

		frameLoader = new FrameLoaderCache(frameLoader);

		AnimBuilder ab = new AnimBuilder(frameLoader);
		Bear.loadGraphics(ab);
		Gem.loadGraphics(ab);

		bear = new Bear();
		bear.c.x = 2500;
		bear.c.y = 950;

		String filename = String.format("C:\\Users\\david\\Desktop\\newdata\\blocks\\%s.png", "w");
		blocksHolder = new BlocksHolder(16, 8, new FileOpenable(filename));

		String filename2 = String
				.format("C:\\Users\\david\\Desktop\\newdata\\blocks\\%sm.png", "w");
		world.maskHolder = new MasksHolder(16, new FileOpenable(filename2));
		// boolean a = maskHolder.test(0, 15, 15);
		// boolean b = maskHolder.test(1, 15, 15);
		// assert a!=b;

		try {
			String filename3 = "C:\\Users\\david\\Desktop\\newdata\\maps\\w0.map";
			FileOpenable src = new FileOpenable(filename3);
			InputStream i = src.open();
			DataInputStream di = new DataInputStream(i);

			// get the game map off the front of the stream
			world.gameMap = new GameMap(di);
			
			// read the other things
			for (;;) {
				String id = readChunkId(di);
				if (id.equals("set2")) {
					bear.c.x = di.readShort();
					bear.c.y = di.readShort();
					int playerFace = di.readByte();
					for (int r=0x30-5; r-->0;) {
						di.readByte();
					}
				}
				else if (id.equals("obj2")) {
					int objectCnt = 0;
					for (;;) {
						int x = di.readShort(); 
						int y = di.readShort();
						if (x<0) break;
						int type = di.readByte();
						int flags = di.readByte();
						int left = di.readShort();
						int top = di.readShort();
						int right = di.readShort();
						int bottom = di.readShort();
						for (int r=12; r-->0;) {
							di.readByte();
						}
						objectCnt++;
						if (type==2 || type==3) {
							boolean wobble = (flags & 1<<3)==0;
							alienList.add(new Gem(x, y, wobble));
						}
					}
					System.out.println(objectCnt);
				}
				else if (id.equals("pal2")) {
					while (di.readShort()!=-1) {}
				}
				else if (id.equals("end!")) {
					break;
				}
				else {
					throw new RuntimeException("Unknown chunk: "+id);
				}
			}
			
			world.keys = keys;
			world.screen.x = 970;
			world.screen.y = 864;
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private String readChunkId(DataInputStream di) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int r=4; r-->0;) {
			sb.append((char)di.readByte());
		}
		String id = sb.toString();
		System.out.println("Got chunk: >"+id+"<");
		return id;
	}

	private void drawTheMap() {
		int blockSize = 16;
		int blockMask = blockSize - 1;

		int sh = (SCREEN_HEIGHT + blockMask) / blockSize + 1;
		int sw = (SCREEN_WIDTH + blockMask) / blockSize + 1;
		int[] blockrow = new int[sw];

		int screenX = world.screen.x;
		int screenY = world.screen.y;
		int pixelDestY = -blockSize + ((~screenY) & blockMask);
		int blockSrcY = screenY / blockSize;
		for (int loopY = 0; loopY < sh; loopY++) {
			int pixelDestX = -blockSize + ((~screenX) & blockMask);
			int blockSrcX = screenX / blockSize;
			for (int loopX = 0; loopX < sw; loopX++) {
				blockrow[loopX] = world.gameMap.getBlock(blockSrcX + loopX, blockSrcY);
			}
			blocksHolder.draw(blockrow, pixelDestX, pixelDestY);
			pixelDestY += blockSize;
			blockSrcY++;
		}
	}

	private void drawEverything() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);

		GlTools.configureFor2dBobs();
		drawTheMap();
		bear.draw(world);
		for (Alien alien : alienList) {
			alien.draw(world);
		}
		myFont.draw(50, 50, 0x00ff00, 0, String.format("kisses 4 charlotte %08d!", frameNumber));
	}

	private void moveEverything() {
		bear.move(world);
		for (Alien alien : alienList) {
			alien.move(world);
		}
		world.scrollTowards(bear.c);
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

	private void startTheExample() {
		initLwjgl();
		initOpenGL();
		initGfx();

		Openable o = new FileOpenable("C:\\Users\\david\\Desktop\\newdata\\font\\topaz.png");
		myFont = new MyFont(OpenableTools.mustLoad(o), 8, 8, false, MyFont.characterRangeHelper(0,
				128));

		// Openable o = new
		// FileOpenable("C:\\Users\\david\\Desktop\\newdata\\font\\font2.png");
		// myFont = new MyFont(OpenableTools.mustLoad(o), 16, 11, true,
		// "abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()' ");

		int requested_fps = 100;
		fpsRep = new FpsReporter(200);
		while (!closing) {
			Display.sync(requested_fps);

			handleKeyboard();

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
		textureExample.startTheExample();
	}
}