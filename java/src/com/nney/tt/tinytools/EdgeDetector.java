package com.nney.tt.tinytools;

public final class EdgeDetector {
	private boolean current;
	private boolean last;
	
	public EdgeDetector next(boolean b) {
		last = current;
		current = b;
		return this;
	}
	
	public boolean current() {
		return current;
	}
	
	public boolean pressed() {
		return !last && current;
	}
	
	public boolean released() {
		return last && !current;
	}
}
