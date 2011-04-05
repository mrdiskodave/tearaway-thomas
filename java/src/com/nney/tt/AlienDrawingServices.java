package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public interface AlienDrawingServices {
	int randomness(int n);
	void drawSprite(Coord c, Sprite s);
	void debugText(Coord c, String text);
}