package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class XLift implements Lift {
	private static final int EXTRA_WIDTH = 4;

	Sprite ourSprite;
	Coord ourPlace = new Coord();

	private Coord lastPlace = new Coord();

	private final LiftAlien parent;

	public XLift(Sprite firstFrame, LiftAlien parent) {
		ourSprite = firstFrame;
		this.parent = parent;
	}

	@Override
	public Coord lastFrameDelta() {
		parent.generateInternalStateFromFrameNumber();
		Coord delta = ourPlace.copy();
		delta.sub(lastPlace);
		return delta;
	}

	public void setPos(Coord c) {
		lastPlace = ourPlace.copy();
		ourPlace = c;
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
}
