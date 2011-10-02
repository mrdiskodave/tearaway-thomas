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

	void reinstate(Alien alien);
	
	Alien instantiateAttachConnect(AlienInfo alienInfo);

	void load(Alien alien);

	Anim mapperLoadAnim(String animsName);

	void setBlockConfig(Config c);
}
