package com.nney.tt.lwjgl;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.tt.Const;
import com.nney.tt.World;
import com.nney.tt.input.KeyboardJoystick;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.PointerAdapter;

public class Main {
	private static final int ZOOM = 2;

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	private World world;

	private boolean closing;

	private FpsReporter fpsRep;

	private void initLwjgl() {
		try {
			Display.setDisplayMode(new DisplayMode(SCREEN_WIDTH * ZOOM, SCREEN_HEIGHT * ZOOM));
			Display.create();
			Display.setVSyncEnabled(true);
			Keyboard.create();
			Keyboard.enableRepeatEvents(true);
			Mouse.create();
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

	// ---------------------------------------------------------------------------

	private void run() {
		initLwjgl();
		initOpenGL();

		LwjglKeyboard keys = new LwjglKeyboard();
		KeyboardJoystick joystick = new KeyboardJoystick(keys);
		GlGraphicsContext gc = new GlGraphicsContext();

		LwjglPointer wonkyMouse = new LwjglPointer();
		// adapt the mouse to compensate for our glOrtho/glViewport screen
		// projection
		Pointer correctMouse = new PointerAdapter(wonkyMouse) {
			@Override
			public int getX() {
				return super.getX() / 2;
			}

			@Override
			public int getY() {
				return SCREEN_HEIGHT - 1 - super.getY() / 2;
			}
		};

		world = new World(gc, joystick, keys, correctMouse);

		int requestedFps = Const.FPS;
		fpsRep = new FpsReporter(200);
		while (!closing) {
			Display.sync(requestedFps);

			keys.handleKeyboard();
			joystick.update();
			wonkyMouse.update();

			GlTools.configureFor2dBobs();
			world.updateEverything();

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
		new Main().run();
	}
}
