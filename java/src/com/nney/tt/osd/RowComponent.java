package com.nney.tt.osd;

import java.util.ArrayList;


public class RowComponent implements Component {
	final private ArrayList<Component> items = new ArrayList<Component>();
	private final int justify;

	public RowComponent(int justify) {
		this.justify = justify;
	}
	
	public void add(Component n) {
		items.add(n);
	}

	@Override
	public int width() {
		int answer = 0;
		for (Component item: items) {
			answer += item.width();
		}
		return answer;
	}

	@Override
	public int height() {
		int answer = 0;
		for (Component item: items) {
			answer = Math.max(answer, item.height());
		}
		return answer;
	}

	@Override
	public void draw(int dx, int dy) {
		int h = height();
		for (Component item: items) {
			int adjustment = Justify.y(justify, item.height(), h);
			item.draw(dx, dy+adjustment);
			dx += item.width();
		}
	}
}
