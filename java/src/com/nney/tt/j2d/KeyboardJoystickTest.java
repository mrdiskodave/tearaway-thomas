package com.nney.tt.j2d;

import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.KeyboardJoystick;

import junit.framework.TestCase;

/** The keys both front ends use for the stick (the LWJGL one had only the original's). */
public class KeyboardJoystickTest extends TestCase {
	private final AwtKeyboard keys = new AwtKeyboard();
	private final KeyboardJoystick stick = new KeyboardJoystick(keys);

	private int with(int key) {
		keys.inject(key, true);
		keys.update();
		int j = stick.get();
		keys.inject(key, false);
		keys.update();
		return j;
	}

	public void testCursorKeys() {
		assertEquals(Joystick.LEFT, with(Keyboard.KEY_LEFT));
		assertEquals(Joystick.RIGHT, with(Keyboard.KEY_RIGHT));
		assertEquals(Joystick.UP, with(Keyboard.KEY_UP));
		assertEquals(Joystick.DOWN, with(Keyboard.KEY_DOWN));
	}

	public void testOriginalKeys() {
		assertEquals(Joystick.UP, with(Keyboard.KEY_Q));
		assertEquals(Joystick.DOWN, with(Keyboard.KEY_A));
		assertEquals(Joystick.LEFT, with(Keyboard.KEY_LBRACKET));
		assertEquals(Joystick.RIGHT, with(Keyboard.KEY_RBRACKET));
	}

	public void testFireKeys() {
		assertEquals(Joystick.FIRE, with(Keyboard.KEY_SPACE));
		assertEquals(Joystick.FIRE, with(Keyboard.KEY_CONTROL));
		assertEquals(Joystick.FIRE, with(Keyboard.KEY_Z));
		assertEquals(0, stick.get());
	}
}
