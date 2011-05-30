package com.nney.tt.input;

public interface HasKeys {
	/**
	 * Check if a key is down.
	 * 
	 * @param key
	 *            The key code to check.
	 * @return <code>true</code> meaning "the key is pressed" or
	 *         <code>false</code> meaning "the key is not pressed".
	 */
	boolean isDown(int key);

	/**
	 * Which key has just been pressed? Only one key can be pressed per period.
	 * If two keys or more are pressed in a period then this method returns the
	 * last one. A period is generally a game frame (e.g. one fiftieth of a
	 * second) so this is not as shoddy as it sounds.
	 * 
	 * @return The key code of the key just pressed or <code>0</code> if
	 *         nothing has been pressed recently.
	 */
	int justPressed();
}

