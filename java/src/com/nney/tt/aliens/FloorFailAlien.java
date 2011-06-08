package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Box;

public class FloorFailAlien extends AlienWithLocation {
	static final private int MAP_EDITS[][] = { { 143, 0, 142 }, { 14, 0, 15 } };

	private int strength = 3;
	
	@Override
	public void update() {
		Box box = new Box(-9, 0, 9, 80).add2(c);
		System.out.println(box.width());
		if (srv.collideBoxWithPlayer(box)) {
			srv.drawDebugText(c.copyAndAdd(-30, -30), "hello");
			Player p = srv.getThePlayer();
			if (p.getTouchDownVel()>=8) {
				if (!srv.isMapping() && strength--<0) {
					srv.applyMapEdits(c.copyAndAdd(-16, 16), MAP_EDITS);
				}
			}
		}
		
		// TODO: player needs to be jumping for it to count?
		// TODO: player needs to fall right through when it breaks?
	}
	
	@Override
	public void mapperUpdate() {
		srv.drawDebugText(c, "Floor Fail");
	}

}
