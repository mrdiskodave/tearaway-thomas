package com.nney.tt.osd;


public class GridComponent implements Component {
	final static Component NULL_COMPONENT = new SpacerComponent(0, 0);

	private static final int LOW = 1;
	private static final int HIGH = 2;
	
	public static final int NORTH = LOW<<4;
	public static final int SOUTH = HIGH<<4;
	public static final int WEST  = LOW;
	public static final int EAST  = HIGH;
	public static final int NORTHWEST = NORTH|WEST;
	public static final int NORTHEAST = NORTH|EAST;
	public static final int SOUTHWEST = SOUTH|WEST;
	public static final int SOUTHEAST = SOUTH|EAST;
	public static final int CENTRED = 0;
	
	int padding;
	
	class Cell {
		int justify = NORTHWEST;
		Component content = NULL_COMPONENT;
	}
	
	final private Cell[] items;
	private final int w;
	private final int h;

	private int horizontalPadding;
	private int verticalPadding;
	
	public GridComponent(int w, int h) {
		this.w = w;
		this.h = h;
		items = new Cell[w*h];
		for (int x=0; x<items.length; x++) {
			items[x] = new Cell();
		}
	}
	
	private int idx(int x, int y) {
		assert x<w;
		assert y<h;
		return y*w+x;
	}
	
	private Cell cell(int x, int y) {
		return items[idx(x, y)];
	}
	
	public void setJustify(int x, int y, int j) {
		cell(x, y).justify = j;
	}
	
	public void setJustify(int j) {
		for (int x=0; x<items.length; x++) {
			items[x].justify = j;
		}
	}
	
	public void setContent(int x, int y, Component c) {
		cell(x, y).content = c;
	}
	
	private int widthOfCol(int x) {
		int r = 0;
		for (int y=0; y<h; y++) {
			r = Math.max(r, cell(x, y).content.width());
		}
		return horizontalPadding*2+r;
	}

	private int heightOfRow(int y) {
		int r = 0;
		for (int x=0; x<w; x++) {
			r = Math.max(r, cell(x, y).content.height());
		}
		return verticalPadding*2+r;
	}
	
	@Override
	public int width() {
		int r = 0;
		for (int x=0; x<w; x++) {
			r += widthOfCol(x);
		}
		return r;
	}

	@Override
	public int height() {
		int r = 0;
		for (int y=0; y<h; y++) {
			r += heightOfRow(y);
		}
		return r;
	}

	@Override
	public void draw(int dx, int dy) {
		dx += horizontalPadding;
		dy += verticalPadding;
		
		int[] widths = new int[w];
		for (int x=0; x<w; x++) {
			widths[x] = widthOfCol(x);
		}
		
		for (int y=0; y<h; y++) {
			int tmpx = dx;
			int hor = heightOfRow(y);
			for (int x=0; x<w; x++) {
				int woc = widths[x];
				Cell cell = cell(x, y); 
				cell.content.draw(tmpx+justify(cell.justify, cell.content.width(), woc), dy+justify(cell.justify>>4, cell.content.height(), hor));
				tmpx += woc; 
			}
			dy += hor;
		}
	}

	private int justify(int justify, int content, int cell) {
		justify &= 0xf;
		if (justify==LOW) return 0;
		if (justify==HIGH) return cell-content;
		return (cell-content)/2;
	}
	
	public void setHorizontalPadding(int horizontalPadding) {
		this.horizontalPadding = horizontalPadding;
	}

	public void setVerticalPadding(int verticalPadding) {
		this.verticalPadding = verticalPadding;
	}
}
