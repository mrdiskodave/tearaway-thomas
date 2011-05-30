package com.nney.tt.input;

import com.nney.utils.Math2;

public class LocksKeyboard implements HasKeys {
	
	private final HasKeys target;

	public LocksKeyboard(HasKeys target) {
		this.target = target;
	}

	@Override
	public boolean isDown(int key) {
		if (!tis(key & (~Locks.ALL))) return false;
		if (Math2.maskTest(key, Locks.CONTROL) && !isCtrl()) return false;
		if (Math2.maskTest(key, Locks.SHIFT) && !isShift()) return false;
		return true;
	}

	@Override
	public int justPressed() {
		int k = target.justPressed();
		if (k == 0) return 0;
		if (isCtrl()) k |= Locks.CONTROL;
		if (isShift()) k |= Locks.SHIFT;
		return k;

	}

	private boolean isShift() {
		return tis(Keyboard.KEY_LSHIFT) || tis(Keyboard.KEY_RSHIFT);
	}

	private boolean isCtrl() {
		return tis(Keyboard.KEY_LCONTROL) || tis(Keyboard.KEY_RCONTROL);
	}

	private boolean tis(int q) {
		return target.isDown(q);
	}
}
