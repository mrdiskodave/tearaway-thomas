package com.nney.tt.aliens;

import com.nney.BitOp;
import com.nney.tt.geom.XRange;

public class LeftRightAlien extends Alien {
	protected XRange range;
	protected boolean headedRight;

	boolean moveLeftRight(int speed) {
		if (headedRight) {
			changeAnimation("right");
			c.x += speed;
			if (c.x > range.right) {
				headedRight = false;
				return true;
			}
		}
		else {
			changeAnimation("left");
			c.x -= speed;
			if (c.x < range.left) {
				headedRight = true;
				return true;
			}
		}
		return false;
	}

	@Override
	public void load() {
		range = new XRange(loadShort(OBleft), loadShort(OBright));
		headedRight = BitOp.test(loadByte(OBflags), 0);
	}

}
