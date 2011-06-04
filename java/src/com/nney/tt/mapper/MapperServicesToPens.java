package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface MapperServicesToPens extends ButtonPressServices {
	void changeCurrentBlock(int x, int y);

	int getCurrentBlock();

	void setCurrentBlockFromMap(Coord c);

	void scroll(Coord delta);

	EditDestination startBlockEdit();

	void endBlockEdit();

	void selectNearestAlien(Coord c);

	void showSelectedAlienProps();

	BatRecord findBat(Coord c);

	Coord getNudge();

	void startAlienEdit();

	void endAlienEdit();

	ButtonRecord findButton(Coord c);
	
	HoverStatus getHoverStatus();

	void perhapsPaste();

	void keyboardBlockChoice(boolean theMainThing);
}
