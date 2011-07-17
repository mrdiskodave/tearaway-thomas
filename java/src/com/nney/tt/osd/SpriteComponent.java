package com.nney.tt.osd;

import com.nney.tt.sprites.Sprite;

public class SpriteComponent implements Component {
	private final Sprite target;

	public SpriteComponent(Sprite target) {
		this.target = target;
	}

	@Override
	public int width() {
		return target.width();
	}

	@Override
	public int height() {
		return target.height();
	}

	@Override
	public void draw(int x, int y) {
		target.draw(x, y);
	}

}
