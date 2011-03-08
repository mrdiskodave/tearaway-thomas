package com.nney;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

/**
 * Show's two boxes of colors according to two theories of how glcolor3ui()
 * might work. See the two inner classes RenderColourBoxAsPerLinuxManPage and
 * RenderColourBoxAsPerOpenGlExample for more info.
 * 
 * <p>
 * RenderColourBoxAsPerLinuxManPage is the only one that comes out correct and
 * is shown on the left.
 */
public class ColorBox {
	private static final int SCREEN_HEIGHT = 600;
	private static final int SCREEN_WIDTH = 800;

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
		GL11.glClearColor(0.0f, 0.0f, 0.0f, 0.0f);

		GL11.glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);

		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_DITHER);
		GL11.glDisable(GL11.GL_FOG);
		GL11.glDisable(GL11.GL_LIGHTING);
		GL11.glDisable(GL11.GL_TEXTURE_1D);
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glShadeModel(GL11.GL_FLAT);
	}

	private static int makeMask(int x) {
		int a = -1;
		a <<= x;
		return ~a;
	}

	/**
	 * <b>Scales</b> it up within the byte because this <a
	 * href="http://linux.die.net/man/3/glcolor3ui">man page</a> talks about the
	 * "largest representable value" probably meaning
	 * "the largest represent value of that particular type" i.e. 255 here.
	 * 
	 * <p>
	 * Does work. Produces 2^16 unique colors.
	 */
	class RenderColourBoxAsPerLinuxManPage extends Renderer {
		@Override
		public int extract(int value, int bitPosition, int bitWidth) {
			int mask = makeMask(bitWidth);
			value >>>= bitPosition;
			value &= mask;

			int answer = value * 255;
			answer /= mask;
			return answer;
		}
	}

	/**
	 * <b>Shifts</b> it up against the top of the byte just as this <a
	 * href="http://www.opengl.org/resources/faq/technical/color.htm">opengl
	 * example</a> does.
	 * 
	 * <p>
	 * Does not work. Of the 2^16 pixels produced many (although unique color
	 * values are sent) are taken as duplicate colors by OpenGL (4993
	 * duplicates, as it turns out).
	 */
	class RenderColourBoxAsPerOpenGlExample extends Renderer {
		@Override
		public int extract(int value, int bitPosition, int bitWidth) {
			int mask = makeMask(bitWidth);
			value >>>= bitPosition;
			value &= mask;

			int answer = value << (8 - bitWidth);
			return answer;
		}
	}

	abstract class Renderer {
		abstract int extract(int value, int bitPosition, int bitWidth);

		void render(int xDisplacement) {
			int redBits = GL11.glGetInteger(GL11.GL_RED_BITS);
			int greenBits = GL11.glGetInteger(GL11.GL_GREEN_BITS);
			int blueBits = GL11.glGetInteger(GL11.GL_BLUE_BITS);

			int colorBits = redBits + greenBits + blueBits;
			if (colorBits != 16) {
				throw new RuntimeException(
						"This demo is only for HighColor/16bit color displays ... change to 16bit color and run again?");
			}
			int numPrims = 1 << colorBits;
			int lengthOfBoxEdge = 1 << (colorBits / 2);
			for (int indx = 0; indx < numPrims; indx++) {
				int r = extract(indx, greenBits + blueBits, redBits);
				int g = extract(indx, blueBits, greenBits);
				int b = extract(indx, 0, blueBits);
				GL11.glColor3ub((byte) r, (byte) g, (byte) b);
				int x = indx % lengthOfBoxEdge + xDisplacement;
				int y = indx / lengthOfBoxEdge + 50;
				GL11.glRectf(x, y, x + 1, y + 1);
			}
		}
	}

	private void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		new RenderColourBoxAsPerLinuxManPage().render(50);
		new RenderColourBoxAsPerOpenGlExample().render(SCREEN_WIDTH / 2);
	}

	private void startTheExample() {
		initLwjglDisplay();
		initOpenGL();
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
		ColorBox cb = new ColorBox();
		cb.startTheExample();
	}
}