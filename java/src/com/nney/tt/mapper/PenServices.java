package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface PenServices extends ButtonPressServices {
	void changeCurrentBlock(int x, int y);

	int getCurrentBlock();

	void scroll(Coord delta);

	void setCurrentBlockFromMap(Coord c);

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
