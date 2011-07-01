package com.nney.tt.gfx;


public class SpacerComponent implements Component {
	private final int width;
	private final int height;

	public SpacerComponent(int width, int height) {
		this.width = width;
		this.height = height;
	}

	@Override
	public int width() {
		return width;
	}

	@Override
	public int height() {
		return height;
	}

	@Override
	public void draw(int dx, int dy) {
		// do nothing
	}
}
