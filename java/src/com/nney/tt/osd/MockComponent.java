package com.nney.tt.osd;

public class MockComponent implements Component {
	private int w;
	private int h;
	private String drawnAt;

	MockComponent(int w, int h) {
		this.w = w;
		this.h = h;

	}

	@Override
	public int width() {
		return w;
	}

	@Override
	public int height() {
		return h;
	}

	@Override
	public void draw(int x, int y) {
		drawnAt = String.format("%sx%s", x, y);
	}

	String drawnAt() {
		return drawnAt;
	}
}
