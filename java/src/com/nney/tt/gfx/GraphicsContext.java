package com.nney.tt.gfx;

import com.nney.utils.Openable;

public interface GraphicsContext {

	void fillRectangle(int x, int y, int w, int h, int col);

	Horizon loadHorizon(Openable ho);

	Blitable createBlitable(SimpleImage i);

	BlocksHolder createBlocksHolder(BlockSource bs);

	// TODO: hide all these params inside -- just wanna pass a font name
	Font createFont(byte[] data, int miniW, int miniH, boolean proportional, String characters);

	int screenWidth();

	int screenHeight();

	void antiCircle(int radius, int x, int y, int c);

}