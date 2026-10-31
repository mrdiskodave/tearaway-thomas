package com.nney.tt.input;

/**
 * The joystick from the keyboard: the original's keys (Q A [ ] and space) and
 * the cursor keys, with space, Ctrl or Z to fire. Both front ends use it.
 */
public class KeyboardJoystick implements Joystick {
	private final Keyboard keyboard;

	public KeyboardJoystick(Keyboard target) {
		this.keyboard = target;
	}

	@Override
	public int get() {
		int x = 0;
		if (keyboard.isDown(Keyboard.KEY_Q)) {
			x |= Joystick.UP;
		}
		if (keyboard.isDown(Keyboard.KEY_A)) {
			x |= Joystick.DOWN;
		}
		if (keyboard.isDown(Keyboard.KEY_LBRACKET)) {
			x |= Joystick.LEFT;
		}
		if (keyboard.isDown(Keyboard.KEY_RBRACKET)) {
			x |= Joystick.RIGHT;
		}
		if (keyboard.isDown(Keyboard.KEY_SPACE)) {
			x |= Joystick.FIRE;
		}
		if (keyboard.isDown(Keyboard.KEY_UP)) x |= Joystick.UP;
		if (keyboard.isDown(Keyboard.KEY_DOWN)) x |= Joystick.DOWN;
		if (keyboard.isDown(Keyboard.KEY_LEFT)) x |= Joystick.LEFT;
		if (keyboard.isDown(Keyboard.KEY_RIGHT)) x |= Joystick.RIGHT;
		if (keyboard.isDown(Keyboard.KEY_CONTROL) || keyboard.isDown(Keyboard.KEY_Z)) x |= Joystick.FIRE;
		return x;
	}
}
