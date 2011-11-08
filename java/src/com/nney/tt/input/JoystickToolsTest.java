package com.nney.tt.input;

import junit.framework.TestCase;

public class JoystickToolsTest extends TestCase {

	public void test() throws Exception {
		t(Joystick.UP);
		t(Joystick.DOWN);
		t(Joystick.LEFT);
		t(Joystick.RIGHT);
		t(Joystick.FIRE);
		t(Joystick.LEFT + Joystick.FIRE); 
		
	}

	private void t(int j1) {
		String s = JoystickTools.joystickToString((byte) j1);
		int j2 = JoystickTools.stringToJoystick(s);
		assertEquals(j1, j2);
	}
}
