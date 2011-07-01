package com.nney.tt.gfx;

import java.util.ArrayList;

public class RowComponent implements Component {
	final private ArrayList<Component> items = new ArrayList<Component>();
	
	public void add(Component n) {
		items.add(n);
	}

	@Override
	public int width() {
		int w = 0;
		for (Component item: items) {
			w += item.width();
		}
		return w;
	}

	@Override
	public int height() {
		int h = 0;
		for (Component item: items) {
			h = Math.max(h, item.height());
		}
		return h;
	}

	@Override
	public void draw(int dx, int dy) {
		int h = height();
		for (Component item: items) {
			int adjustment = computeAdjustment(item.height(), h);
			item.draw(dx, dy+adjustment);
			dx += item.width();
		}
	}

	private int computeAdjustment(int itemSize, int totalSize) {
		// centred!
		// other adjustments? YAGNI
		return (totalSize-itemSize)/2;
	}
}
