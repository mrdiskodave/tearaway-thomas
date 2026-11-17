package com.nney.tt.osd;

public class ResizableGrid<T> {
	private Grid<T> grid;

	ResizableGrid(int w, int h) {
		grid = new Grid<>(w, h);
	}

	public T get(int x, int y) {
		return grid.get(x, y);
	}

	public void set(int x, int y, T t) {
		grid.set(x, y, t);
	}

	public int width() {
		return grid.width();
	}

	public int height() {
		return grid.height();
	}

	public void setSize(int w, int h) {
		Grid<T> ng = new Grid<>(w, h);
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				T t = null;
				if (x < width() && y < height()) t = get(x, y);
				ng.set(x, y, t);
			}
		}
		grid = ng;
	}

	public String dump() {
		StringBuilder sb = new StringBuilder();
		for (int y = 0; y < height(); y++) {
			if (y != 0) sb.append('|');
			for (int x = 0; x < width(); x++) {
				if (x != 0) sb.append(',');
				sb.append(get(x, y));
			}
		}
		return sb.toString();
	}
}
