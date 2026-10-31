package com.nney.tt.lwjgl;

import java.io.File;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.ContextCapabilities;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;
import org.lwjgl.opengl.GLContext;

import com.nney.tt.Const;
import com.nney.tt.OuterWorld;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.KeyboardJoystick;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.PointerAdaptor;
import com.nney.tt.resources.TTResource;

public class LwjglMain {
	/**
	 * Throw when LWJGL closes us. e.g. when the window is closed
	 */
	static public class ExitException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	// used to be: 290/255

	public static boolean GL_ARB_texture_rectangle;

	public static boolean GL_ARB_texture_non_power_of_two;

	public static boolean GL_EXT_framebuffer_object;

	/** Where the game's picture goes in the window (OpenGL's coordinates: from the bottom left). */
	private static int viewX, viewY, viewW, viewH, windowW, windowH;

	/**
	 * Open the window, or go full screen, and fit the game's 4:3 picture in it:
	 * as big as it goes, a whole-number zoom if that's close, black around it.
	 */
	private void initLwjgl() {
		try {
			DisplayMode dm;
			if (fullScreen) {
				dm = Display.getDesktopDisplayMode();
				Display.setDisplayModeAndFullscreen(dm);
			}
			else {
				dm = new DisplayMode((int) Math.round(SCREEN_WIDTH * scale), (int) Math.round(SCREEN_HEIGHT * scale));
				Display.setDisplayMode(dm);
			}
			windowW = dm.getWidth();
			windowH = dm.getHeight();
			double s = Math.min((double) windowW / SCREEN_WIDTH, (double) windowH / SCREEN_HEIGHT);
			if (s >= 1 && s - Math.floor(s) < 0.15) s = Math.floor(s);
			viewW = (int) Math.round(SCREEN_WIDTH * s);
			viewH = (int) Math.round(SCREEN_HEIGHT * s);
			viewX = (windowW - viewW) / 2;
			viewY = (windowH - viewH) / 2;
			Display.setTitle("Tearaway Thomas");
			Display.create();
			Display.setVSyncEnabled(true);
			Keyboard.create();
			Keyboard.enableRepeatEvents(true);
			Mouse.create();

			ContextCapabilities cap = GLContext.getCapabilities();
			GL_ARB_texture_rectangle = cap.GL_ARB_texture_rectangle;
			GL_ARB_texture_non_power_of_two = cap.GL_ARB_texture_non_power_of_two;
			GL_EXT_framebuffer_object = cap.GL_EXT_framebuffer_object;
		}
		catch (LWJGLException e) {
			throw new RuntimeException(e);
		}
	}

	private void initOpenGL() {
		GlTools.reset();

		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glClearColor(0.0f, 0.5f, 1.0f, 0.0f);

		GL11.glViewport(viewX, viewY, viewW, viewH);
		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}

	/**
	 * At the start of each frame: black everywhere (the game draws its whole
	 * picture, but not the borders around it), then back to the picture.
	 */
	static void clearBorders() {
		if (viewW == windowW && viewH == windowH) return;
		GL11.glViewport(0, 0, windowW, windowH);
		GL11.glClearColor(0f, 0f, 0f, 1f);
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		GL11.glViewport(viewX, viewY, viewW, viewH);
	}

	// ---------------------------------------------------------------------------

	private int level = -1;
	private double scale = 2;
	private boolean fullScreen;
	private boolean dev;
	private boolean mapper;
	private boolean beep;
	private String soundDevice;

	/** The options that make sense for this front end (see J2dMain for the rest). */
	private void parse(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String a = args[i];
			if (a.equals("--beep")) beep = true;
			else if (a.equals("--sound-device")) soundDevice = args[++i];
			else if (a.equals("--level")) level = Integer.parseInt(args[++i]);
			else if (a.equals("--scale")) {
				String v = args[++i];
				if (v.equals("full")) fullScreen = true;
				else scale = com.nney.tt.j2d.J2dMain.parseScale(v);
			}
			else if (a.equals("--dev")) dev = true;
			else if (a.equals("--mapper")) mapper = true;
			else if (a.equals("--resources")) TTResource.setResourcePath(new File(args[++i]));
			else throw new IllegalArgumentException("Unknown option with --lwjgl: " + a);
		}
	}

	private void run() {
		try {
			LwjglNatives.prepare();
		}
		catch (IllegalStateException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}
		initLwjgl();
		initOpenGL();

		// the title pages are drawn from a coroutine, on another thread: the
		// OpenGL context has to go back and forth with control
		com.nney.coroutines.Coroutine.setHandover(new com.nney.coroutines.Coroutine.Handover() {
			@Override
			public void release() {
				try {
					if (Display.isCurrent()) Display.releaseContext();
				}
				catch (LWJGLException e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			public void acquire() {
				try {
					if (!Display.isCurrent()) Display.makeCurrent();
				}
				catch (LWJGLException e) {
					throw new RuntimeException(e);
				}
			}
		});

		final AlAudioContext audioContext = new AlAudioContext(soundDevice);

		final LwjglKeyboard keys = new LwjglKeyboard();
		final KeyboardJoystick joystick = new KeyboardJoystick(keys);

		final LwjglPointer wonkyMouse = new LwjglPointer();
		// adapt the mouse to compensate for our glOrtho/glViewport screen
		// projection (the picture's position and size, and y up the window)
		Pointer correctMouse = new PointerAdaptor(wonkyMouse) {
			@Override
			public int getX() {
				int x = (super.getX() - viewX) * SCREEN_WIDTH / viewW;
				return Math.max(0, Math.min(SCREEN_WIDTH - 1, x));
			}

			@Override
			public int getY() {
				int y = SCREEN_HEIGHT - 1 - (super.getY() - viewY) * SCREEN_HEIGHT / viewH;
				return Math.max(0, Math.min(SCREEN_HEIGHT - 1, y));
			}

			@Override
			public void set(int x, int y) {
				super.set(viewX + x * viewW / SCREEN_WIDTH, viewY + (SCREEN_HEIGHT - 1 - y) * viewH / SCREEN_HEIGHT);
			}
		};

		GlGraphicsContext gc = new GlGraphicsContext(Const.FPS, new Runnable() {
			@Override
			public void run() {
				keys.update();
				wonkyMouse.update();
				audioContext.update();
			}
		}, new Runnable() {
			@Override
			public void run() {
				keys.clear();
			}
		});

		OuterWorld ow = new OuterWorld(gc, audioContext, joystick, keys, correctMouse);
		ow.devMode = dev || mapper;
		if (mapper) ow.launchMapper(new Coord(0, 0));
		else ow.launchFullGame(level);

		try {
			ow.run();
		}
		catch (ExitException x) {
		}

		ow.dispose();
		audioContext.dispose();
		Mouse.destroy();
		Keyboard.destroy();
		Display.destroy();
	}

	/**
	 * The OpenGL front end. Normally started with
	 * <code>java -jar tearaway-thomas.jar --lwjgl</code>.
	 */
	public static void main(String[] argv) {
		LwjglMain m = new LwjglMain();
		try {
			m.parse(argv);
		}
		catch (IllegalArgumentException | IndexOutOfBoundsException e) {
			com.nney.tt.j2d.J2dMain.badOptions(e);
		}
		if (m.beep) {
			AlBeep.run(m.soundDevice);
			return;
		}
		m.run();
		System.exit(0);
	}
}
