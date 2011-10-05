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

	/**
	 * Which key was pressed in this period? At most one key can be pressed per
	 * period. If two keys or more are pressed in a period then this method
	 * returns the most recent key. A period is generally very short (e.g. one
	 * fiftieth of a second) so this is not as shoddy as it sounds.
	 * 
	 * <p>
	 * Note that the return value is fixed for the whole period and not cleared,
	 * for example, by calling this method.
	 * 
	 * @return A key code (see {@link Keyboard}) or <code>0</code> if nothing
	 *         was pressed in this period.
	 */
	int justPressed();

	/**
	 * A numeric identifier for the period mentioned in {@link #justPressed()}.
	 * This is useful if you are wrapping this interface. The wrapper will need
	 * to call the underlying {@link #justPressed()} only once no matter how
	 * many it itself is called.
	 * 
	 * @return The period number.
	 */
	int periodNumber();
}
