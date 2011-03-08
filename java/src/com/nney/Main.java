package com.nney;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.utils.FileOpenable;

public class Main {
	private static final int SCREEN_WIDTH = 400*2;
	private static final int SCREEN_HEIGHT = 300*2;

	private Anim anim;
	private BlocksHolder blocksHolder;
	private int counter;
	private long lastTime;
	private int scrollX;
	private MasksHolder maskHolder;
	private GameMap gameMap;

	private void initLwjglDisplay() {
		try {
			Display.setDisplayMode(new DisplayMode(SCREEN_WIDTH, SCREEN_HEIGHT));
			Display.create();
			Display.setVSyncEnabled(true);
		}
		catch (LWJGLException e) {
			throw new RuntimeException(e);
		}
	}

	private void initOpenGL() {
		discoverDisplayDepth();
		GlTools.reset();
		
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glClearColor(1.0f, 0.5f, 1.0f, 0.0f);

		GL11.glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);

		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH/2, SCREEN_HEIGHT/2, 0, 1, -1);
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

	private void initTexture() {
		LargeImageFrameLoader frameLoader = new LargeImageFrameLoader() {
			@Override
			FileOpenable findData(Frame f) {
				// all that is missing is knowledge of how to find those large frames!
				String filename = String.format("C:\\Users\\david\\Desktop\\newdata\\bobs\\%s_%d.png", f.name, f.number);
				return new FileOpenable(filename);
			}
		};

		FrameSource frameHub = new FrameSource(new FrameFinder(), frameLoader);
		Bear bear = new Bear();
		bear.loadGraphics(frameHub);
		anim = bear.walkingRight;
		
		String filename = String.format("C:\\Users\\david\\Desktop\\newdata\\blocks\\%s.png", "w");
		blocksHolder = new BlocksHolder(16, 8, new FileOpenable(filename));

		String filename2 = String.format("C:\\Users\\david\\Desktop\\newdata\\blocks\\%sm.png", "w");
		maskHolder = new MasksHolder(16, new FileOpenable(filename2));
		boolean a = maskHolder.test(0, 15, 15);
		boolean b = maskHolder.test(1, 15, 15);
		assert a!=b;
		
		String filename3 = "C:\\Users\\david\\Desktop\\newdata\\maps\\w0.map";
		gameMap = new GameMap(new FileOpenable(filename3));
	}

	/**
	 * Draw a quad with the texture on it.
	 */
	private void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		GlTools.configureFor2dBobs();


		// scrolling map demo
		int dx, dy=0;
		int px = scrollX/16;
		for (int demoY=0; demoY<20; demoY++) {
			dx = ((~scrollX)&15)-16;
			for (int demoX=0; demoX<30; demoX++) {
				int blockNumber = gameMap.getBlock(50+demoX+px, 54+demoY);
				assert blockNumber>=0;
				blocksHolder.draw(blockNumber, dx, dy);
				dx += 16;
			}
			dy += 16;
		}
		scrollX += 1;
		
		// animation demo
		dx = 100;
		dy = 100;
		anim.next().draw(dx, dy);

	}

	private void startTheExample() {
		initLwjglDisplay();
		initOpenGL();
		initTexture();
		
		int count = 200;
		int requested_fps = 50;

		lastTime = System.nanoTime();
		while (true) {
			render();

			Display.update();
			Display.sync(requested_fps);

			if (Display.isCloseRequested()) {
				Display.destroy();
				break;
			}
		
			counter ++;
			if (counter==count) {
				counter = 0;
				long past = lastTime;
				long present  = System.nanoTime();
				float diff = present - past;
				diff /= 1000000000;
				float actual_fps = (float) count / diff;
				Display.setTitle("FPS: "+actual_fps);
				
				lastTime = System.nanoTime(); 
			}
		}
	}

	public static void main(String[] argv) {
		Main textureExample = new Main();
		textureExample.startTheExample();
	}
}