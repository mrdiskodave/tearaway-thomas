package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface MapperServicesToPens extends ButtonPressServices {
	void selectNearestAlien(Coord c);

	void showSelectedAlienProps();

	BatRecord findBat(Coord c);

	Coord getNudge();

	void startAlienEdit();

	void endAlienEdit();

	ButtonRecord findButton(Coord c);
	
	HoverStatus getHoverStatus();
}
