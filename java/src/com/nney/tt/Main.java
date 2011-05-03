package com.nney.tt;

import java.util.HashSet;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.GlTools;

public class Main {

	private static final int ZOOM = 2;

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	private World world = new World();

	private boolean closing;

	private FpsReporter fpsRep;

	public HashSet<Integer> keys = new HashSet<Integer>();

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

	private int readJoystick() {
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
		return x;
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

	// ---------------------------------------------------------------------------

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
		world.init2();
		
		
		world.init();

		int requestedFps = 50;
		fpsRep = new FpsReporter(200);
		while (!closing) {
			Display.sync(requestedFps);

			handleKeyboard();

			world.drawEverything(readJoystick());

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
