package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class FloorFailAlien extends AlienWithLocation {
	static final private int MAP_EDITS[][] = { { 143, 0, 142 }, { 14, 0, 15 } };

	private int strength = 3;
	
	@Override
	public void update() {
		Coord d = c.copy();
		d.and(-16, -16);
		d.y += 16;
		d.x --;
		Box box = Box.fromTopLeftAndSize(d, 18, 16);
		freezeBounds = box;
		if (srv.collideBoxWithPlayerHandle(box)) {
			srv.drawDebugText(c, "hello");
			Player p = srv.getThePlayer();
			if (p.getTouchDownVel()>=8) {
				if (--strength<=0) {
					srv.applyMapEdits(c.copyAndAdd(-16, 16), MAP_EDITS);
				}
			}
		}
	}
	
	@Override
	public void mapperUpdate() {
		srv.drawDebugText(c, "Floor Fail");
	}

}
