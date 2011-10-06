package com.nney.tt.input;

public interface Locks {
	static final int LOCK_SHIFT = 1<<16;
	static final int LOCK_CONTROL = 2<<16;
	static final int LOCK_MENU = 4<<16;
	static final int LOCK_ALL = 7<<16;
}
