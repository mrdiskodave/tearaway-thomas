package com.nney.tt.aliens;

import com.nney.tt.geom.Box;

public class ScoreGivingAlien extends AlienWithLocation {
	int amount = 50;
	
	@Override
	public void update() {
		Box b = boxAroundUs(7);
		freezeBounds = b;
		if (amount>0 && srv.collideBoxWithPlayer(b)) {
			srv.giveScore(100, null);
			if (!srv.isMapping()) {
				amount--;
				if (amount==0) {
					done();
				}
			}
		}
	}
	
	@Override
	public void mapperUpdate() {
		srv.drawDebugText(c, "Hidden Score");
	}
}
