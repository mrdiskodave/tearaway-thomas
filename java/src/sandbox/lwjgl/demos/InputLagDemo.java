package sandbox.lwjgl.demos;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Mouse;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;

public class InputLagDemo {
	private static final boolean INPUT_SHOULD_LAG_BY_ONE_FRAME = true;

	/**
	 * Does set up, calls {@link #test()}, then does tear down.
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
		for (;;) {
			if (INPUT_SHOULD_LAG_BY_ONE_FRAME) {
				Display.update();
				Display.sync(1);
			}
			else {
				Display.update(false);
				Display.sync(1);
				Display.processMessages();
			}
			if (Display.isCloseRequested()) break;
			System.out.println(String.format("%d button %s", frame++, Mouse.isButtonDown(0)));
		}
	}

	public static void main(String[] args) {
		new InputLagDemo().executeTest();
	}
}