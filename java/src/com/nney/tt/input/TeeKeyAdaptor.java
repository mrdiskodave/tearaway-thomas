package com.nney.tt.input;             

/**
 * Merge multiple things with keys ({@link HasKeys}) into one.
 */
public class TeeKeyAdaptor implements HasKeys {
	private HasKeys[] things;

	public TeeKeyAdaptor(HasKeys... things) {
		this.things = things;
	}
	
	@Override
	public boolean isDown(int key) {
		for (HasKeys thing: things) {
			if (thing.isDown(key)) return true;
		}
		return false;
	}

	@Override
	public KeyEvent nextEvent() {
		for (HasKeys thing: things) {
			KeyEvent e = thing.nextEvent();
			if (e!=null) return e;
		}
		return null;
	}
}
