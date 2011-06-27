package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

@AlienInfoAnns({ @AlienInfoAnn(type = 8, gfx = "0arru"), @AlienInfoAnn(type = 9, gfx = "0arrd"),
		@AlienInfoAnn(type = 10, gfx = "0arrl"), @AlienInfoAnn(type = 11, gfx = "0arrr") })
public class ArrowAlien extends AlienWithLocation {
	private int repeat;

	@AlienProp(name = "AdviceBox", doc = "Player's location for us to blink at him?", label = "adviceBox")
	public Box box = new Box(0, 0, 0, 0);

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(c, 50);
		box.add(new Coord(25, 0));
	}

	@Override
	public void onLoaded() {
		depth = DEPTH_FOREGROUND;
	}

	@Override
	public void loadFromLegacyData() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		boolean collide = box.inside(srv.getPlayerPosition());
		if (collide) {
			repeat = 8;
		}

		boolean on = false;
		if (repeat != 0) {
			int frm = srv.getFrameNumber() & 31;
			if (frm < 22) {
				on = true;
			}
			else if (frm == 31) {
				repeat--;
			}
		}

		if (on) {
			changeAnimation(0);
			Sprite s = nextFrame();
			srv.drawSprite(c, s);
		}
	}
}
