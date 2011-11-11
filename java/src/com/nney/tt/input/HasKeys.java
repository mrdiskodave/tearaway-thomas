package com.nney.tt.input;

public interface HasKeys {
	/**
	 * Check if a key is down.
	 * 
	 * @param key
	 *            The key code to check (see {@link Keyboard}).
	 * @return <code>true</code> meaning "the key is pressed" or
	 *         <code>false</code> meaning "the key is not pressed".
	 */
	boolean isDown(int key);

	KeyEvent nextEvent();
}
