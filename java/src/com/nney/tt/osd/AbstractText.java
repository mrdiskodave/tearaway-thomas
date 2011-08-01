package com.nney.tt.osd;

import com.nney.tt.gfx.Disposable;

public abstract class AbstractText implements Component, Disposable {
	public void centredDraw(int x, int y) {
		int nx = x - width() / 2;
		draw(nx, y);
	}
}
