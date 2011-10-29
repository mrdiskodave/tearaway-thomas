package com.nney.tt.input;             

/**
 * Merge multiple things with keys ({@link HasKeys}) into one.
 */
public class TeeKeyAdaptor extends KeyAdaptor {
	private HasKeys[] things;

	public TeeKeyAdaptor(HasKeys... things) {
		super(things[0]);
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
	protected int getNext() {
		for (HasKeys thing: things) {
			int k = thing.justPressed();
			if (k!=0) return k;
		}
		return 0;
	}
}
