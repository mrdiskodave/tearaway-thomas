package com.nney.tt.input;             

public class TeeKeyAdaptor extends KeyAdaptor {
	private HasKeys[] hks;

	public TeeKeyAdaptor(HasKeys... hks) {
		super(hks[0]);
		this.hks = hks;
	}
	
	@Override
	public boolean isDown(int key) {
		for (HasKeys hk: hks) {
			if (hk.isDown(key)) return true;
		}
		return false;
	}

	@Override
	protected int getNext() {
		for (HasKeys hk: hks) {
			int k = hk.justPressed();
			if (k!=0) return k;
		}
		return 0;
	}
}
