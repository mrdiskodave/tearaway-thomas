package com.nney;

/*
 * I've been trying and failing to get an -exact- blit of a 2D sprite and have boiled it down to this:
 * 
 * This example makes and draws a 16x16 texture of rgb:0xf2/0xf2/0xf2 
 * resulting in a 16x16 on-screen box of an entirely different colour: rgb:0xef/0xf3/0xef (239/243/239)
 * which is very strange!
 * 
 * Can anyone explain why?
 */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.Pump;

public class TextureExample {
	private static final int SCREEN_HEIGHT = 600;
	private static final int SCREEN_WIDTH = 800;

	private static final int FRAMES = 8;
	
	private Bob[] bob = new Bob[FRAMES];
	private int currentFrame;
	
	private void configureTextureEngine() {
		GL11.glEnable(GL11.GL_BLEND);
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_REPLACE);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_S, GL11.GL_CLAMP);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_T, GL11.GL_CLAMP);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_NEAREST);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_NEAREST);
	}

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
		resetOpenGl();

		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glClearColor(0.5f, 0.5f, 0.0f, 0.0f);

		GL11.glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);

		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}

	private void resetOpenGl() {
		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_DITHER);
		GL11.glDisable(GL11.GL_FOG);
		GL11.glDisable(GL11.GL_LIGHTING);
		GL11.glDisable(GL11.GL_TEXTURE_1D);
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glShadeModel(GL11.GL_FLAT);
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
		AnimSpec w = new AnimSpec(128, new FramesSpec("wbear", 0, 1, 2, 3, 4, 5, 6, 7));
		
		
		for (int x=0; x<FRAMES; x++) {
			byte[] b;
			try {
				Openable openable = new FileOpenable("C:\\Users\\david\\Desktop\\newdata\\bobs\\wbear_00"+Integer.toString(x)+".png");
				b = loadIntoByteArray(openable);
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
			
			bob[x] = Bob.fromLargeImage(b);
		}
	}

	private byte[] loadIntoByteArray(Openable openable) throws IOException {
		InputStream in = openable.open();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		new Pump(in, out).processToEof();
		return out.toByteArray();
	}

	/**
	 * Draw a quad with the texture on it.
	 */
	private void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		configureTextureEngine();

		int dx = 100;
		int dy = 100;

		bob[currentFrame].draw(dx, dy);
		
		currentFrame++;
		currentFrame %= FRAMES;
	}

	private void startTheExample() {
		initLwjglDisplay();
		initOpenGL();
		initTexture();

		while (true) {
			render();

			Display.update();
			Display.sync(15);

			if (Display.isCloseRequested()) {
				Display.destroy();
				break;
			}
		}
	}

	public static void main(String[] argv) {
		TextureExample textureExample = new TextureExample();
		textureExample.startTheExample();
	}
}