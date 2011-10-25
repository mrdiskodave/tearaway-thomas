package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

@AlienInfoAnns({ @AlienInfoAnn(type = 8, gfx = "0arru", name = "arrowUp"), @AlienInfoAnn(type = 9, gfx = "0arrd", name = "arrowDown"),
		@AlienInfoAnn(type = 10, gfx = "0arrl", name = "arrowLeft"), @AlienInfoAnn(type = 11, gfx = "0arrr", name = "arrowRight") })
public class ArrowAlien extends AlienWithLocation {
	private int repeatCounter;

	@PropAnn(doc = "Player's location for us to blink at him?")
	public Box adviceBox = new Box(0, 0, 0, 0);

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		adviceBox = Box.around(c, 50);
		adviceBox.add(new Coord(25, 0));
	}

	@Override
	public void onLoaded() {
		depth = DEPTH_FG_SCENARY;
	}

	@Override
	public void loadFromLegacyData() {
		adviceBox = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	@Override
	public void update() {
		boolean collide = adviceBox.inside(srv.getPlayerPosition());
		if (collide) {
			repeatCounter = 8;
		}

		boolean on = false;
		if (repeatCounter != 0) {
			int frm = srv.getFrameNumber();
			int frm31 = frm & 31;
			if (frm31 < 22) {
				on = true;
			}
			else if (frm31 == 31) {
				repeatCounter--;
			}
		}

		if (on && srv.showText()) {
			changeAnimation(0);
			Sprite s = nextFrame();
			srv.drawSprite(c, s);
		}
	}
}
