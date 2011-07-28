package com.nney.tt.osd;

import java.util.ArrayList;

public class ColComponent implements Component {
	final private ArrayList<Component> items = new ArrayList<Component>();
	
	public void add(Component n) {
		items.add(n);
	}

	@Override
	public int height() {
		int answer = 0;
		for (Component item: items) {
			answer += item.height();
		}
		return answer;
	}

	@Override
	public int width() {
		int answer = 0;
		for (Component item: items) {
			answer = Math.max(answer, item.height());
		}
		return answer;
	}

	@Override
	public void draw(int dx, int dy) {
		int w = width();
		for (Component item: items) {
			int adjustment = computeHorizontalAdjustment(item.height(), w);
			item.draw(dx+adjustment, dy);
			dy += item.height();
		}
	}

	private int computeHorizontalAdjustment(int itemSize, int totalSize) {
		// vertically centred!
		// the only adjustment for now.
		return (totalSize-itemSize)/2;
	}
}
