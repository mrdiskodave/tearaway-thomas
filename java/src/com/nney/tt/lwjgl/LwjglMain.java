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

	static final int ZOOM = 2;

	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	// used to be: 290/255

	public static boolean GL_ARB_texture_rectangle;

	public static boolean GL_ARB_texture_non_power_of_two;

	public static boolean GL_EXT_framebuffer_object;

	private void initLwjgl() {
		try {
			Display.setDisplayMode(new DisplayMode(SCREEN_WIDTH * ZOOM, SCREEN_HEIGHT * ZOOM));
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

		GL11.glViewport(0, 0, SCREEN_WIDTH * ZOOM, SCREEN_HEIGHT * ZOOM);
		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}

	// ---------------------------------------------------------------------------

	private int level = -1;
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
		// projection
		Pointer correctMouse = new PointerAdaptor(wonkyMouse) {
			@Override
			public int getX() {
				return super.getX() / 2;
			}

			@Override
			public int getY() {
				return SCREEN_HEIGHT - 1 - super.getY() / 2;
			}

			@Override
			public void set(int x, int y) {
				x *= 2;
				y = SCREEN_HEIGHT - 1 - y;
				y *= 2;
				super.set(x, y);
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
