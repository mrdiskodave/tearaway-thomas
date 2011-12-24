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
		if (!horizontalOverlap(obNow.x)) {
			return false;
		}

		int ls = liftLast.y - 1;
		int le = liftNow.y - 1;

		// consider the lift
		// if it is going upwards then
		if (ls > le) {
			// swap the two values so 'ls'
			// is the lesser
			int t = ls;
			ls = le;
			le = t;
		}

		// consider the given object
		// if it is going upwards then
		int os = obLast.y;
		int oe = obNow.y;
		if (os > oe) {
			// swap the two values so 'os'
			// is the lesser
			int t = os;
			os = oe;
			oe = t;

			// we know the object is going up
			// if it also above the lift ..
			if (os < ls) {
				// .. then NO
				return false;
			}
		}

		// otherwise ...
		// we do a (tunnelling proof) test of range overlap

		assert ls <= le; // lift range
		assert os <= oe; // object range

		// return: do the two ranges overlap?
		boolean rangesOverlap = !(le < os || oe < ls);
		return rangesOverlap;
	}

	@Override
	public void leave() {
		System.out.println("LEAVE!");
	}
}
