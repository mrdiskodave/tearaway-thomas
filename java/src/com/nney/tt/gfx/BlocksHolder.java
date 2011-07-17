package com.nney.tt.gfx;

public interface BlocksHolder extends Disposable {

	void draw(int[] blocks, int dx, int dy);

	void draw(int block, int dx, int dy);

	int getBlockCount();
}