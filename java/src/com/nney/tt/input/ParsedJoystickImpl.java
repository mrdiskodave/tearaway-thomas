package com.nney.tt.input;

import com.nney.utils.Math2;

public class ParsedJoystickImpl implements ParsedJoystick {
	private int jdx;
	private int jdy;
	private boolean fire;

	@Override
	public int x() {
		return jdx;
	}

	@Override
	public int y() {
		return jdy;
	}

	@Override
	public boolean fire() {
		return fire;
	}

	private int getStickDelta(int stick, int less, int more) {
		int delta = 0;
		if (Math2.maskTest(stick, less)) delta--;
		if (Math2.maskTest(stick, more)) delta++;
		return delta;
	}

	public void set(int stick) {
		jdx = getStickDelta(stick, Joystick.LEFT, Joystick.RIGHT);
		jdy = getStickDelta(stick, Joystick.UP, Joystick.DOWN);
		fire = Math2.maskTest(stick, Joystick.FIRE);
	}
}
