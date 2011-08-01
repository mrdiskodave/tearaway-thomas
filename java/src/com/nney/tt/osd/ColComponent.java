package com.nney.tt.osd;

import java.util.ArrayList;

public class ColComponent implements Component {
	final private ArrayList<Component> items = new ArrayList<Component>();
	private int justify;
	
	public void add(Component n) {
		items.add(n);
	}

	public ColComponent(int justify) {
		this.justify = justify;
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
			answer = Math.max(answer, item.width());
		}
		return answer;
	}

	@Override
	public void draw(int dx, int dy) {
		int w = width();
		for (Component item: items) {
			int adjustment = Justify.x(justify, item.width(), w);
			item.draw(dx+adjustment, dy);
			dy += item.height();
		}
	}
}
