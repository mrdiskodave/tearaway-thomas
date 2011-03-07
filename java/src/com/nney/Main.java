package com.nney;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.utils.FileOpenable;

public class Main {
	private static final int SCREEN_HEIGHT = 600;
	private static final int SCREEN_WIDTH = 800;

	private Anim anim;
	private BlocksHolder bh;
	private int counter;
	private long lastTime;
	private int qqq;

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
		GL11.glClearColor(0.5f, 0.5f, 0.0f, 0.0f);

		GL11.glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);

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
		anim = bear.climbing;
		
		bh = new BlocksHolder(16, 8);
		bh.load();
	}

	/**
	 * Draw a quad with the texture on it.
	 */
	private void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		GlTools.configureFor2dBobs();

		int dx=0, dy=0;

		
		
		for (int z=0; z<40; z++) {
			dx = qqq;
			dy += 16;
			for (int b=0; b<50; b++) {
				bh.draw(b, dx, dy);
				dx += 16;
			}
		}
		qqq += 1;
		
		dx = 100;
		dy = 100;
		anim.next().draw(dx, dy);

	}

	private void startTheExample() {
		initLwjglDisplay();
		initOpenGL();
		initTexture();
		
		int count = 100;

		lastTime = System.nanoTime();
		while (true) {
			render();

			Display.update();
			Display.sync(50);

			if (Display.isCloseRequested()) {
				Display.destroy();
				break;
			}
		
			counter ++;
			if (counter==count) {
				counter = 0;
				long t = lastTime;
				lastTime = System.nanoTime(); 
				float z = lastTime - t;
				z /= 1000000000;
				float fps = (float) count / z;
				Display.setTitle("FPS: "+fps);
			}
		}
	}

	public static void main(String[] argv) {
		Main textureExample = new Main();
		textureExample.startTheExample();
	}
}