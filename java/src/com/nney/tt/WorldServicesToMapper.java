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

	void reinstate(Alien alien);

	void load(Alien alien);
	
	Anim mapperLoadAnim(String animsName);

	BlocksHolder getBlocksHolder();

	void setBlockConfig(boolean seeMasks, boolean seeHidden);

	boolean playerFall(Coord where, int fallMax);
}
