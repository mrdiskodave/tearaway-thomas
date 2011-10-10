package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
import com.nney.tt.sprites.Anim;
import com.nney.utils.Math2;

public abstract class LeftRightAlien extends AlienWithLocation {
	@AlienProp(name = "Range", doc = "The horizontal span in which we move.", label = "range")
	public XRange range;

	@AlienProp(name = "Facing", xtraDef = "leftright", label = "goLeft")
	public boolean goLeft;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		range.around(c.x, 50);
		range.add(25);
	}

	@Override
	public Anim mapperAnim() {
		return anims.find(goLeft ? "left" : "right");
	}

	boolean moveLeftRight(int speed) {
		if (!goLeft) {
			changeAnimation("right");
			c.x += speed;
			if (c.x > range.right) {
				goLeft = true;
				return true;
			}
		}
		else {
			changeAnimation("left");
			c.x -= speed;
			if (c.x < range.left) {
				goLeft = false;
				return true;
			}
		}
		return false;
	}

	@Override
	public void loadFromLegacyData() {
		range = new XRange(loadShort(OBleft), loadShort(OBright));
		goLeft = !Math2.bitTest(loadByte(OBflags), 0);
	}
}
