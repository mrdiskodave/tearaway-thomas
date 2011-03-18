package com.nney.lwjgl.demos;

import java.nio.ByteBuffer;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

public class MonoBlitExample {
	private static final int SCREEN_HEIGHT = 200;
	private static final int SCREEN_WIDTH = 300;

	private static final int TEXTURE_WIDTH = 32;
	private static final int TEXTURE_HEIGHT = 32;

	private int textureId;

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
	private void resetOpenGl() {
		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_DITHER);
		GL11.glDisable(GL11.GL_FOG);
		GL11.glDisable(GL11.GL_LIGHTING);
		GL11.glDisable(GL11.GL_TEXTURE_1D);
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glShadeModel(GL11.GL_FLAT);
	}

	private void initOpenGL() {
		resetOpenGl();
		
		GL11.glClearColor(1.0f, 1.0f, 0.0f, 0.0f);
		
		GL11.glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
	
		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}
	private void initTexture() {
		// generate a texture that is a blue triangle
		ByteBuffer buffer = ByteBuffer.allocateDirect(TEXTURE_WIDTH*TEXTURE_HEIGHT);
		for (int y=0; y<TEXTURE_HEIGHT; y++) {
			for (int x=0; x<TEXTURE_WIDTH; x++) {
//				int a = x>y ? 0x00 : 0xff;
				int a = (255*x)/TEXTURE_WIDTH;
				buffer.put((byte) a); // A
			}
		}
		buffer.rewind();

		
		// store it under a textureId
		textureId = GL11.glGenTextures();
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_S, GL11.GL_CLAMP);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_T, GL11.GL_CLAMP);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_NEAREST);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_NEAREST);
		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, GL11.GL_ALPHA, TEXTURE_WIDTH, TEXTURE_HEIGHT, 0,
				GL11.GL_ALPHA, GL11.GL_UNSIGNED_BYTE, buffer);
		
//		GL_ALPHA    : RGBA = (0, 0, 0, X)
//		GL_LUMINANCE: RGBA = (X, X, X, 1)
//		GL_INTENSITY: RGBA = (X, X, X, X)
	}

	/**
	 * Draw a quad with the texture on it.
	 */
	private void render() {
		// clear the screen
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		
		// configure the texture engine
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		
		GL11.glColor3f(1.0f, 0.0f, 1.0f);
		
		GL11.glEnable(GL11.GL_BLEND);

//		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_MODULATE);
//		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_REPLACE);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);
//		GL11.glBlendFunc(GL11.GL_ONE, GL11.GL_ZERO);

		// bind the texture
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
		
		// draw a quad with our texture on it
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
			Display.sync(20);

			if (Display.isCloseRequested()) {
				Display.destroy();
				break;
			}
		}
	}

	public static void main(String[] argv) {
		new MonoBlitExample().startTheExample();
	}
}


