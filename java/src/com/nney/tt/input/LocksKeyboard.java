package com.nney.tt.input;

import com.nney.utils.Math2;

public class LocksKeyboard implements HasKeys {
	
	private final HasKeys target;

	public LocksKeyboard(HasKeys target) {
		this.target = target;
	}

	@Override
	public boolean isDown(int key) {
		if (Math2.maskTest(key, Shifts.CONTROL) && !isCtrl()) return false;
		if (Math2.maskTest(key, Shifts.SHIFT) && !isShift()) return false;
		key &= ~Shifts.ALL;
		if (key==0) return true;
		return tis(key);
	}

	@Override
	public int justPressed() {
		int k = target.justPressed();
		if (k == 0) return 0;
		if (isCtrl()) k |= Shifts.CONTROL;
		if (isShift()) k |= Shifts.SHIFT;
		return k;

	}

	private boolean isShift() {
		return tis(Keyboard.KEY_SHIFT);
	}

	private boolean isCtrl() {
		return tis(Keyboard.KEY_CONTROL);
	}

	private boolean tis(int q) {
		return target.isDown(q);
	}
}
