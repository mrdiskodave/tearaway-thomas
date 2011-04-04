package com.nney;

public interface AlienDrawingServices {
	int randomness(int n);
	void drawSprite(Coord c, Sprite s);
	void debugText(Coord c, String text);
}