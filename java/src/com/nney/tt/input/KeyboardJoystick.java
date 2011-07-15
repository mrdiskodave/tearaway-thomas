package com.nney.tt.input;

public class KeyboardJoystick extends PartialJoystickImpl {
	private final Keyboard keyboard;

	public KeyboardJoystick(Keyboard target) {
		this.keyboard = target;
	}

	public void update() {
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
		setNext(x);
	}
}
