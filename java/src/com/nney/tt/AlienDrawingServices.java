package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public interface AlienDrawingServices {
	int randomness(int n);
	void queueSprite(Coord c, Sprite s);
	void queueDebugText(Coord c, String text);
}