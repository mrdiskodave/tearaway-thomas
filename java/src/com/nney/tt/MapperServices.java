package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;

public interface MapperServices {
	void quitMapper(Coord newPlayerPosition);
	void drawMap();
	void moveScreen(Coord delta);
	Coord getScreenPosition();
	void mapperDrawAliens();
	void addNewAlien(Alien alien);
	Alien findNearestAlien(Coord c);

	
	
	int getFrameNumber();
}
