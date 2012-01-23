package sandbox.lwjgl.demos;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;

/**
 * The issue discussed in http://lwjgl.org/forum/index.php?topic=3247.0 still
 * seems to be hanging around. This class demonstrates the problem in Windows
 * with 2.7.1 and with 2.8.1.
 */
public class InputLagDemo {
	private static final boolean INPUT_SHOULD_LAG_BY_ONE_FRAME = true;

	/**
	 * Does set up, calls {@link #test()}, then tears down.
	 */
	public void executeTest() {
		try {
			Display.setDisplayMode(new DisplayMode(640, 640));
			Display.setVSyncEnabled(true);
			Display.create();
			Mouse.create();
		}
		catch (LWJGLException e) {
			throw new RuntimeException(e);
		}

		test();

		Mouse.destroy();
		Display.destroy();
	}

	/**
	 * The actual test.
	 */
	private void test() {
		int frame = 0;
		while (!Display.isCloseRequested()) {
			if (INPUT_SHOULD_LAG_BY_ONE_FRAME) {
				// get input lag:
				Display.update();
				Display.sync(1);
			}
			else {
				// avoid input lag:
				Display.update(false);
				Display.sync(1);
				Display.processMessages();
			}
			System.out.println(String.format("%d button %s", frame++, Mouse.isButtonDown(0)));
		}
	}

	public static void main(String[] args) {
		new InputLagDemo().executeTest();
	}
}