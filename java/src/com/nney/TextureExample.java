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

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import javax.imageio.ImageIO;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

import com.nney.utils.ClassResourceOpenable;

public class TextureExample {
	private static final int SCREEN_HEIGHT = 600;
	private static final int SCREEN_WIDTH = 800;

	private static final int TEXTURE_WIDTH = 16;
	private static final int TEXTURE_HEIGHT = 16;
	private static final int TEXTURE_PIXELS = TEXTURE_WIDTH * TEXTURE_HEIGHT;
	private static final int TEXTURE_CHANNELS = 3;
	private static final int TEXTURE_BUFFER_SIZE = TEXTURE_CHANNELS * TEXTURE_PIXELS;

	private int textureId;

	private void bindTexture() {
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
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
		int r = GL11.glGetInteger(GL11.GL_RED_BITS);
		int g = GL11.glGetInteger(GL11.GL_GREEN_BITS);
		int b = GL11.glGetInteger(GL11.GL_BLUE_BITS);
		System.out.println("colour bits:");
		System.out.println(r);
		System.out.println(g);
		System.out.println(b);
		
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glClearColor(0.0f, 0.0f, 0.0f, 0.0f);

		// GL11.glEnable(GL11.GL_BLEND);
		// GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);
		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_DITHER);
		GL11.glDisable(GL11.GL_FOG);
		GL11.glDisable(GL11.GL_LIGHTING);
		GL11.glDisable(GL11.GL_TEXTURE_1D);
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glShadeModel(GL11.GL_FLAT);
		
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_DECAL);

		GL11.glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);

		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}

	private void initTexture() {
		InputStream is;
		try {
			is = new ClassResourceOpenable(TextureExample.class, "000.png").open();
			BufferedImage i = ImageIO.read(is);
			int w = i.getWidth();
			int h = i.getHeight();
			int[] pixels = i.getRGB(0, 0, w, h, null, 0, w);
			for (int y=0; y<h; y++) {
				for (int x=0; x<w; x++) {
					int o = w*y + x;
					int p = pixels[o];
					System.out.println(String.format("%03d %03d %08x", x, y, p));
				}
			}
			int z = 5;
			z++;
			
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		
		textureId = GL11.glGenTextures();
		bindTexture();
		ByteBuffer buffer = ByteBuffer.allocateDirect(TEXTURE_BUFFER_SIZE);
		for (int x = 0; x < TEXTURE_PIXELS; x++) {
			for (int c = 0; c < TEXTURE_CHANNELS; c++) {
				buffer.put((byte) x);
			}
		}
		buffer.rewind();

		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, GL11.GL_RGB8, TEXTURE_WIDTH, TEXTURE_HEIGHT, 0,
				GL11.GL_RGB, GL11.GL_UNSIGNED_BYTE, buffer);
	}

	/**
	 * Draw a quad with the texture on it.
	 */
	private void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		bindTexture();
		
		float destination = 100f;
		int scale = 1;

		GL11.glBegin(GL11.GL_QUADS);
		GL11.glTexCoord2f(0, 0);
		GL11.glVertex2f(destination, destination);
		GL11.glTexCoord2f(1, 0);
		GL11.glVertex2f(destination + TEXTURE_WIDTH * scale, destination);
		GL11.glTexCoord2f(1, 1);
		GL11.glVertex2f(destination + TEXTURE_WIDTH * scale, destination + TEXTURE_HEIGHT * scale);
		GL11.glTexCoord2f(0, 1);
		GL11.glVertex2f(destination, destination + TEXTURE_HEIGHT * scale);
		GL11.glEnd();
	}

	private void startTheExample() {
		initLwjglDisplay();
		initOpenGL();
		initTexture();

		while (true) {
			render();

			Display.update();
			Display.sync(10);

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