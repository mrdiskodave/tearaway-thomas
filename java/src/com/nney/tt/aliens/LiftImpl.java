package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class LiftImpl implements Lift {
	private static final int EXTRA_WIDTH = 4;

	Sprite ourSprite;
	final Coord liftNow = new Coord();

	final private Coord liftLast = new Coord();

	/** Width to stand on, or 0 to measure it from the sprite. */
	private final int width;

	public LiftImpl(Sprite firstFrame) {
		this(firstFrame, 0);
	}

	public LiftImpl(Sprite firstFrame, int width) {
		ourSprite = firstFrame;
		this.width = width;
	}

	private int width() {
		return width > 0 ? width : ourSprite.liftWidth();
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
		int width = width() + EXTRA_WIDTH * 2;
		return x >= left && x < left + width;
	}

	public int landOn() {
		return liftNow.y - 1;
	}

	public void centre(Coord coord) {
		coord.x -= width() / 2;
	}

	@Override
	public boolean isScoopingUp(Coord obLast, Coord obNow) {
		// if there isn't a horizontal overlap now
		if (!horizontalOverlap(obNow.x)) {
			// then NO
			// System.out.println("Scoop: No (horiz)");
			return false;
		}

		int ls = liftNow.y - 1;
		int le = liftLast.y - 1;
		int os = obNow.y;
		int oe = obLast.y;

		// System.out.println(String.format("lift %d->%d object %d->%d", le, ls,
		// oe, os));

		// if the object is above the lift
		if (os < ls) {
			// then NO
			// System.out.println("Scoop: No (above)");
			return false;
		}

		// otherwise we need to do something
		// smart enough to avoid any tunnelling
		//
		// a comparison of ranges:

		// get the two ranges in order
		if (ls > le) {
			int t = ls;
			ls = le;
			le = t;
		}
		if (os > oe) {
			int t = os;
			os = oe;
			oe = t;
		}
		assert ls <= le; // lift range
		assert os <= oe; // object range

		// return: do the two ranges overlap?
		boolean answer = !(le < os || oe < ls);
		// System.out.println(String.format("Scoop: lift%d-%d object%d-%d %s)",
		// ls, le, os, oe, answer));
		return answer;
	}

	@Override
	public void leave() {
		System.out.println("LEAVE!");
	}
}
