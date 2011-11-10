package com.nney.tt.mapper;

import com.nney.tt.input.Keyboard;

public interface KeyMap {
	/**
	 * Map a key.
	 * 
	 * @param key A key-code from {@link Keyboard}.
	 * @return A unicode character number or -1 if it doesn't map.
	 */
	int mapKey(int key);
}
