package com.nney.tt.input;

public class LocksKeyAdaptor extends KeyAdaptor {
	public LocksKeyAdaptor(HasKeys target) {
		super(target);
	}

	@Override
	protected int getNext() {
		int k = target.justPressed();
		if (target.isDown(Keyboard.KEY_SHIFT)) k |= Locks.LOCK_SHIFT;
		if (target.isDown(Keyboard.KEY_CONTROL)) k |= Locks.LOCK_CONTROL;
		if (target.isDown(Keyboard.KEY_MENU)) k |= Locks.LOCK_MENU;
		return k;
	}

	/**
	 * This method is just delegated to the target. The only addition is that
	 * you can use it to test <i>single</i> lock <b>instead</b> of testing a
	 * <i>single</i> key. What you cannot do is test, for example if
	 * <code>Ctrl+C</code> is held down. These kinds of tests only make sense
	 * for {@link #justPressed()}.
	 */
	@Override
	public boolean isDown(int key) {
		if (key == Locks.LOCK_SHIFT) key = Keyboard.KEY_SHIFT;
		if (key == Locks.LOCK_CONTROL) key = Keyboard.KEY_CONTROL;
		if (key == Locks.LOCK_MENU) key = Keyboard.KEY_MENU;
		return target.isDown(key);
	}
}
