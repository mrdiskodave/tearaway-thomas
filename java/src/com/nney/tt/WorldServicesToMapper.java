package com.nney.tt;

import com.nney.tt.BlockSet.Config;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.sprites.Anim;

public interface WorldServicesToMapper {
	void quitMapper(Coord newPlayerPosition);

	void drawForMapper();

	Coord getScreenPosition();

	void setScreenPosition(Coord c);

	Alien findNearestAlien(Coord c);

	BlocksHolder getBlocksHolder();

	void reinstateAlien(Alien alien);
	
	Alien mapperCreateAlien(AlienInfo alienInfo);

	void loadAlienIntoWorld(Alien alien);

	Anim loadAnim(String animsName);

	void setBlockConfig(Config c);
}
