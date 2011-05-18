package sandbox.lwjgl.demos;

import java.nio.ByteBuffer;
import java.util.Random;

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
		// I give it RGBA to see what happens.
		//
		// The RGB bit is entirely ignored
		// - it just strips that off and stores the alpha channel.

		// It would be better if we gave it ourFormat==GL_ALPHA in which case
		// we'd be sending just the alpha and the transaction would be
		// completely efficient.
		int ourFormat = GL11.GL_RGBA;
		int theirFormat = GL11.GL_ALPHA;
		Random r = new Random(5);
		ByteBuffer buffer = ByteBuffer.allocateDirect(TEXTURE_WIDTH * TEXTURE_HEIGHT * 4);
		for (int y = 0; y < TEXTURE_HEIGHT; y++) {
			for (int x = 0; x < TEXTURE_WIDTH; x++) {
				int a = x > y ? 0x00 : 0xff;
				// colors of chaos!!! just to show clearly that RGB is ignored
				// (the actual color is chosen later when we render this
				// alpha-only texture)
				buffer.put((byte) r.nextInt()); // R
				buffer.put((byte) r.nextInt()); // G
				buffer.put((byte) r.nextInt()); // B
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
		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, theirFormat, TEXTURE_WIDTH, TEXTURE_HEIGHT, 0, ourFormat,
				GL11.GL_UNSIGNED_BYTE, buffer);

		/*
		 * Quoted from:
		 * http://www.gamedev.net/topic/307568-glteximage2d-questions/
		 * 
		 * GL_ALPHA : RGBA = (0, 0, 0, X)
		 * 
		 * GL_LUMINANCE: RGBA = (X, X, X, 1)
		 * 
		 * GL_INTENSITY: RGBA = (X, X, X, X)
		 * 
		 * In other words, if we interpret the alpha as transparency, GL_ALPHA
		 * would represent a completely black texture with varying transparency,
		 * GL_LUMINANCE is an opaque texture with varying color (a grayscale
		 * image), and GL_INTENSITY is a combination where both the color and
		 * alpha channel is varying.
		 * 
		 * Although the RGB channels of a GL_ALPHA texture are defined to be
		 * black, they don't actually get used during the "standard" tex env
		 * modes. For modulate, replace, blend, and add, the outgoing RGB values
		 * of a texture unit that uses a GL_ALPHA texture are the same as the
		 * incoming RGB values, so the GL_ALPHA texture can only affect the
		 * fragment's alpha values. Of course if you're using a fragment shader
		 * or texture combiners, then you may actually make use of the RGB
		 * values.
		 */
	}

	/**
	 * Draw a quad with the texture on it.
	 */
	private void render() {
		// clear the screen
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);

		// configure the texture system
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glEnable(GL11.GL_BLEND);
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_REPLACE);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);

		// bind the texture
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);

		// HERE is we choose the color and we choose purple
		GL11.glColor3f(1.0f, 0.0f, 1.0f);

		// draw a quad with our texture on it
		int destination = 100;
		GL11.glBegin(GL11.GL_QUADS);
		GL11.glTexCoord2f(0, 0);
		GL11.glVertex2i(destination, destination);
		GL11.glTexCoord2f(1, 0);
		GL11.glVertex2i(destination + TEXTURE_WIDTH, destination);
		GL11.glTexCoord2f(1, 1);
		GL11.glVertex2i(destination + TEXTURE_WIDTH, destination + TEXTURE_HEIGHT);
		GL11.glTexCoord2f(0, 1);
		GL11.glVertex2i(destination, destination + TEXTURE_HEIGHT);
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
