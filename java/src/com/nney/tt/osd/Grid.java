package com.nney.tt.osd;

import java.util.ArrayList;

public class Grid<T> {
	final private ArrayList<T> content;
	final private int width;
	final private int height;

	Grid(int width, int height) {
		this.width = width;
		this.height = height;
		int t = width * height;
		content = new ArrayList<>(t);
		for (int x = 0; x < t; x++) {
			content.add(null);
		}
		assert content.size() == t;
	}

	private int idx(int x, int y) {
		if (x >= width) {
			throw new IllegalArgumentException(x + " when the width is " + width);
		}
		if (y >= height) {
			throw new IllegalArgumentException(y + " when the height is " + height);
		}
		return width * y + x;
	}

	public T get(int x, int y) {
		return content.get(idx(x, y));
	}

	public void set(int x, int y, T t) {
		content.set(idx(x, y), t);
	}

	public int width() {
		return width;
	}

	public int height() {
		return height;
	}
}
