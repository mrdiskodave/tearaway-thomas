package com.nney.tt;

import com.nney.tt.geom.Coord;

public interface MapperServices {
	void quitMapper(Coord newPlayerPosition);
	void drawMap();
	void moveScreen(Coord delta);
	Coord getScreenPosition();
}
