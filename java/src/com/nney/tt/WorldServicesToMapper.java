package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.sprites.Anims;

public interface WorldServicesToMapper {
	void quitMapper(Coord newPlayerPosition);

	void drawMap();

	void drawAliensForMapper();

	void moveScreen(Coord delta);

	Coord getScreenPosition();

	void setScreenPosition(Coord c);

	Alien findNearestAlien(Coord c);

	void toggleSeeMasks();

	void toggleShowInvisible();

	BlocksHolder getBlocksHolder();

	void reinstateAlien(Alien alien);
	
	Alien createAlien(int typeCode);

	void loadAlienIntoWorld(Alien alien);

	Anims loadAnims(String animsName);
}
