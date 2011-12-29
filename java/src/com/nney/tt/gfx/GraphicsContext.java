package com.nney.tt.gfx;

import com.nney.utils.Openable;

public interface GraphicsContext {
	void beginDrawing();

	void endDrawing();

	void fillRectangle(int x, int y, int w, int h, int col);

	Blitable createBlitable(SimpleImage i);

	BlocksHolder createBlocksHolder(BlockSource bs);

	// TODO: hide all these params inside -- just wanna pass a font name
	Font createFont(RawFont rf);

	int screenWidth();

	int screenHeight();

	Horizon loadHorizon(Openable ho);

	void aperture(int radius, int x, int y, int c);
}