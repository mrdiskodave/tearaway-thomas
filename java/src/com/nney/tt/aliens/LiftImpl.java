package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class LiftImpl implements Lift {
	private static final int EXTRA_WIDTH = 4;

	Sprite ourSprite;
	final Coord liftNow = new Coord();

	final private Coord liftLast = new Coord();

	public LiftImpl(Sprite firstFrame) {
		ourSprite = firstFrame;
	}

	@Override
	public Coord lastFrameDelta() {
		return liftNow.sub2(liftLast);
	}

	public void setPos(Coord c) {
		liftLast.copyFieldsFrom(liftNow);
		liftNow.copyFieldsFrom(c);
	}

	@Override
	public boolean horizontalOverlap(int x) {
		int left = liftNow.x - EXTRA_WIDTH;
		int width = ourSprite.liftWidth() + EXTRA_WIDTH * 2;
		return x >= left && x < left + width;
	}

	public int landOn() {
		return liftNow.y - 1;
	}

	public void centre(Coord coord) {
		coord.x -= ourSprite.liftWidth() / 2;
	}

	@Override
	public boolean isScoopingUp(Coord obLast, Coord obNow) {
		// if there isn't a horizontal overlap now
		// then NO
		if (!horizontalOverlap(obNow.x)) return false;

		// consider the given object
		int os = obLast.y;
		int oe = obNow.y;
		// if it is going upwards then NO
		if (os > oe) {
			return false;
		}

		// consider the lift
		int ls = liftLast.y - 1;
		int le = liftNow.y - 1;
		// if it is going upwards then
		if (ls > le) {
			// swap the two values so 'ls'
			// is the lesser
			int t = ls;
			ls = le;
			le = t;
		}

		assert ls <= le; // lift range
		assert os <= oe; // object range

		// return: do the two ranges overlap?
		return !(le < os || oe < ls);
	}
}
