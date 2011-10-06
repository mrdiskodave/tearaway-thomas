package com.nney.tt.input;

public class NullKeyAdaptor extends KeyAdaptor {
	public NullKeyAdaptor(HasKeys target) {
		super(target);
	}

	@Override
	public boolean isDown(int key) {
		return target.isDown(key);
	}

	@Override
	protected int getNext() {
		return target.justPressed();
	}
}
