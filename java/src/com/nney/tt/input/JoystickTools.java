package com.nney.tt.input;

import com.nney.utils.Math2;

public class JoystickTools {
	static private byte[] values = { Joystick.LEFT, Joystick.RIGHT, Joystick.UP, Joystick.DOWN, Joystick.FIRE };

	static private char[] characters = { 'l', 'r', 'u', 'd', 'f' };

	static public String joystickToString(byte c) {
		StringBuilder sb = new StringBuilder();
		for (int x = 0; x < characters.length; x++) {
			if (Math2.maskTest(c, values[x])) sb.append(characters[x]);
		}
		return sb.toString();
	}

	static public byte stringToJoystick(String s) {
		int answer = 0;
		for (int x = 0; x < characters.length; x++) {
			if (s.indexOf(characters[x]) >= 0) answer |= values[x];
		}
		return (byte) answer;
	}
}
