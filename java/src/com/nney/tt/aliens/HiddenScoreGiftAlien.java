package com.nney.tt.aliens;

import com.nney.tt.geom.Box;

public class HiddenScoreGiftAlien extends AlienWithLocation {
	private static final int SCORE_GIVEN = 100;
	private static final int NUMER_OF_TIMES = 50;

	int count = NUMER_OF_TIMES;

	@Override
	public void update() {
		Box b = boxAroundUs(7);
		freezeBounds = b;
		if (count > 0 && srv.collideBoxWithPlayer(b)) {
			srv.awardScore(SCORE_GIVEN, null);
			count--;
		}
	}
}
