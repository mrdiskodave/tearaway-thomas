package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class LiftImpl implements Lift {
	private static final int EXTRA_WIDTH = 4;

	Sprite ourSprite;
	final Coord ourPlace = new Coord();

	final private Coord lastPlace = new Coord();

	public LiftImpl(Sprite firstFrame) {
		ourSprite = firstFrame;
	}

	@Override
	public Coord lastFrameDelta() {
		return ourPlace.sub2(lastPlace);
	}

	public void setPos(Coord c) {
		lastPlace.copyFieldsFrom(ourPlace);
		ourPlace.copyFieldsFrom(c);
	}

	@Override
	public boolean horizontalOverlap(int x) {
		int left = ourPlace.x - EXTRA_WIDTH;
		int width = ourSprite.liftWidth() + EXTRA_WIDTH * 2;
		return x >= left && x < left + width;
	}

	public int landOn() {
		return ourPlace.y - 1;
	}

	public void centre(Coord coord) {
		coord.x -= ourSprite.liftWidth() / 2;
	}
}
