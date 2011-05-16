package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.XRange;

public abstract class LeftRightAlien extends Alien {
	@AlienProp(name = "Facing", xtraDef = "left")
	public boolean goLeft;

	@AlienProp(name = "Range", doc = "The horizontal span in which we walk.")
	public XRange range;

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
	public void load() {
		range = new XRange(loadShort(OBleft), loadShort(OBright));
		goLeft = !BitOp.test(loadByte(OBflags), 0);
	}
}
