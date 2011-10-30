/*
 * Copyright (c) 2002-2008 LWJGL Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of 'LWJGL' nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package sandbox.lwjgl.demos;

import org.lwjgl.LWJGLException;
import org.lwjgl.input.Keyboard;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;

/**
 * <p>
 * A simple test rig that reveals that:
 * 
 * <p>
 * 1 If L/RMENU, L/RCONTROL is pressed then release events from the opposite key
 * are ignored (but press events are not).
 * 
 * <p>
 * 2 If LSHIFT is pressed then all events from RSHIFT are ignored.
 * 
 * <p>
 * 3 Strangest of all: if RSHIFT is pressed then all events from LSHIFT are
 * ignored except that if there is an LSHIFT pressed event while RSHIFT is
 * pressed then when you release RSHIFT you get an LSHIFT(!) released event.
 * e.g.
 * 
 * <p>
 * Actual: Press RSHIFT, Press LSHIFT, Release LSHIFT, Release RSHIFT.
 * 
 * <p>
 * Reported: Press RSHIFT, Release LSHIFT.
 * 
 * <p>
 * Tested on lwjgl2.7.1 and lwjgl2.8.1 on Windows7. Two different physical
 * keyboards used to be safe. I've posted a query here
 * http://lwjgl.org/forum/index.php/topic,4268.0.html .
 * 
 */
public class KeyboardTest {
	private static int WINDOW_WIDTH = 640;

	private static int WINDOW_HEIGHT = 640;

	private void initialize() {
		DisplayMode dm = new DisplayMode(WINDOW_WIDTH, WINDOW_HEIGHT);
		try {
			Display.setDisplayMode(dm);
			Display.setVSyncEnabled(true);
			Display.create();
		}
		catch (LWJGLException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Executes the actual test
	 */
	public void executeTest() {
		initialize();

		runTest();

		Display.destroy();
	}

	/**
	 * Runs the test
	 */
	private void runTest() {
		// while not exiting
		boolean active = true;
		for (;;) {
			Display.update();
			if (Display.isCloseRequested()) break;

			if (Display.isActive()) {
				if (!active) {
					active = true;
					System.out.println("hello");
				}
			}
			else {
				active = false;
			}

			// poll and check keyboard and mouse
			handleKeyboard();

			pause(100);
			Thread.yield();
		}
	}

	/**
	 * Pauses the current thread for a specified time
	 * 
	 * @param time
	 *            milliseconds to pause
	 */
	private static void pause(long time) {
		try {
			Thread.sleep(time);
		}
		catch (InterruptedException inte) {
			inte.printStackTrace();
		}
	}

	/**
	 * Handles the keyboard
	 */
	private void handleKeyboard() {
		while (Keyboard.next()) {
			int keyCode = Keyboard.getEventKey();
			boolean down = Keyboard.getEventKeyState();
			System.out.println(String.format("%s %s", down ? "Press" : "Release", Keyboard.getKeyName(keyCode)));
		}
	}

	/**
	 * @param args
	 *            the command line arguments
	 */
	public static void main(String[] args) {
		KeyboardTest mt = new KeyboardTest();
		mt.executeTest();
		System.exit(0);
	}
}