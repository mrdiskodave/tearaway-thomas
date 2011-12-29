package com.nney.tt.input;

public class LocksKeyAdaptor implements HasKeys {
	private final HasKeys target;

	public LocksKeyAdaptor(HasKeys target) {
		this.target = target;
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

	@Override
	public KeyEvent nextEvent() {
		KeyEvent e = target.nextEvent();
		if (e == null) return null;
		int k = 0;
		if (target.isDown(Keyboard.KEY_SHIFT)) k |= Locks.LOCK_SHIFT;
		if (target.isDown(Keyboard.KEY_CONTROL)) k |= Locks.LOCK_CONTROL;
		if (target.isDown(Keyboard.KEY_MENU)) k |= Locks.LOCK_MENU;
		if (k != 0) {
			e = new KeyEvent(e.keyCode | k, e.keyChar);
		}
		return e;
	}
}
