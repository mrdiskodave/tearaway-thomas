package com.nney.tt.osd;

public class GridComponent implements Component {
	final static Component NULL_COMPONENT = new SpacerComponent(0, 0);

	int padding;

	class Cell {
		int justify = Justify.NORTHWEST;
		Component content = NULL_COMPONENT;
	}

	final private Grid<Cell> items;

	private int horizontalPadding;
	private int verticalPadding;

	public GridComponent(int w, int h) {
		items = new Grid<>(w, h);
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				setCell(x, y, new Cell());
			}
		}
	}

	private void setCell(int x, int y, Cell c) {
		items.set(x, y, c);
	}

	private Cell cell(int x, int y) {
		return items.get(x, y);
	}

	public void setJustify(int x, int y, int j) {
		cell(x, y).justify = j;
	}

	public void setJustify(int j) {
		for (int y = 0; y < items.height(); y++) {
			for (int x = 0; x < items.width(); x++) {
				cell(x, y).justify = j;
			}
		}
	}

	public void setContent(int x, int y, Component c) {
		cell(x, y).content = c;
	}

	private int widthOfCol(int x) {
		int r = 0;
		for (int y = 0; y < items.height(); y++) {
			r = Math.max(r, cell(x, y).content.width());
		}
		return horizontalPadding * 2 + r;
	}

	private int heightOfRow(int y) {
		int r = 0;
		for (int x = 0; x < items.width(); x++) {
			r = Math.max(r, cell(x, y).content.height());
		}
		return verticalPadding * 2 + r;
	}

	@Override
	public int width() {
		int r = 0;
		for (int x = 0; x < items.width(); x++) {
			r += widthOfCol(x);
		}
		return r;
	}

	@Override
	public int height() {
		int r = 0;
		for (int y = 0; y < items.height(); y++) {
			r += heightOfRow(y);
		}
		return r;
	}

	@Override
	public void draw(int dx, int dy) {
		dx += horizontalPadding;
		dy += verticalPadding;

		int[] widths = new int[items.width()];
		for (int x = 0; x < items.width(); x++) {
			widths[x] = widthOfCol(x);
		}

		for (int y = 0; y < items.height(); y++) {
			int tmpx = dx;
			int hor = heightOfRow(y);
			for (int x = 0; x < items.width(); x++) {
				int woc = widths[x];
				Cell cell = cell(x, y);
				cell.content.draw(tmpx + Justify.x(cell.justify, cell.content.width(), woc),
						dy + Justify.y(cell.justify, cell.content.height(), hor));
				tmpx += woc;
			}
			dy += hor;
		}
	}

	public void setHorizontalPadding(int horizontalPadding) {
		this.horizontalPadding = horizontalPadding;
	}

	public void setVerticalPadding(int verticalPadding) {
		this.verticalPadding = verticalPadding;
	}

	public int widthInCells() {
		return items.width();
	}

	public int heightInCells() {
		return items.height();
	}

}
