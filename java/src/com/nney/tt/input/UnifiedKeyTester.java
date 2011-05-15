package com.nney.tt.input;

public class UnifiedKeyTester {
	private final Pointer mouse;
	private final Keyboard keyboard;

	UnifiedKeyTester(Pointer mouse, Keyboard keyboard) {
		this.mouse = mouse;
		this.keyboard = keyboard;
	}
	
	boolean isDown(int key) {
		if (key>=Pointer.KEY_POINTER) {
			return mouse.isDown(key);
		}
		return keyboard.isDown(key);
	}
	
}
