package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface PenServices {
	void changeCurrentBlock(int x, int y);

	int getCurrentBlock();

	void keyboardBlockChoiceAndShow();

	void scroll(Coord delta);

	void setCurrentBlockFromMap(Coord c);

	void showBlocks();

	EditDestination startEdit();

	void endEdit();

	void selectNearestAlien(Coord c);

	void showSelectedAlienProps();

	BatRecord searchForBat(Coord c);

}
