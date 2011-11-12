package com.nney.tt.lwjgl;

import java.io.File;
import java.util.HashSet;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;
import org.lwjgl.opengl.GLContext;

import com.nney.tt.Const;
import com.nney.tt.Launcher;
import com.nney.tt.OuterWorld;
import com.nney.tt.World;
import com.nney.tt.input.KeyboardJoystick;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.PointerAdaptor;
import com.nney.tt.mapper.Mapper;
import com.nney.tt.resources.TTResource;

public class Main {
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

			HashSet<String> capabilities = new HashSet<String>();
			for (String ext : GL11.glGetString(GL11.GL_EXTENSIONS).split(" ")) {
				capabilities.add(ext);
			}

			if (capabilities.contains("GL_ARB_texture_rectangle")) {
				GL_ARB_texture_rectangle = true;
			}
			if (capabilities.contains("GL_ARB_texture_non_power_of_two")) {
				GL_ARB_texture_non_power_of_two = true;
			}
			if (capabilities.contains("GL_EXT_framebuffer_object")) {
				GL_EXT_framebuffer_object = true;
			}
			assert GLContext.getCapabilities().GL_ARB_texture_rectangle == GL_ARB_texture_rectangle;
			assert GLContext.getCapabilities().GL_ARB_texture_non_power_of_two == GL_ARB_texture_non_power_of_two;
			assert GLContext.getCapabilities().GL_EXT_framebuffer_object == GL_EXT_framebuffer_object;

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
		TTResource.setResourcePath(new File("C:\\Users\\david\\Desktop\\z"));

		initLwjgl();
		initOpenGL();

		final AlAudioContext audioContext = new AlAudioContext();

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
		ow.bootstrap = new Launcher() {
			@Override
			public void launch(OuterWorld outerWorld) {
				new Mapper(outerWorld).run();
//				 World w = new World(outerWorld);
//				 w.playLevel();
			}
		};

		try {
			ow.run();
		}
		catch (ApplicationClosedException x) {
		}
		;

		audioContext.dispose();
		Mouse.destroy();
		Keyboard.destroy();
		Display.destroy();
	}

	public static void main(String[] argv) {
		new Main().run();
	}
}
