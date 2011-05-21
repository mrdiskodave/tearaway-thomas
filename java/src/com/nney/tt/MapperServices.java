package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;

public interface MapperServices {
	void quitMapper(Coord newPlayerPosition);

	void drawMap();

	void drawAliensForMapper();

	void moveScreen(Coord delta);

	Coord getScreenPosition();

	void addNewAlien(Alien alien);

	Alien findNearestAlien(Coord c);

	void toggleSeeMasks();

	void toggleShowInvisible();

	BlocksHolder getBlocksHolder();

	void reinstateAlien(Alien alien);

	void setScreenPosition(Coord c);
}
