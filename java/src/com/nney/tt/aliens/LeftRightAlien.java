package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.XRange;
import com.nney.tt.sprites.Sprite;

public abstract class LeftRightAlien extends Alien {
	@AlienProp(name = "Range", doc = "The horizontal span in which we walk.")
	public XRange range;

	@AlienProp(name = "Facing", xtraDef = "leftright")
	public boolean goLeft;

	@Override
	public void mapperUpdate() {
		changeAnimation(goLeft ? "left" : "right");
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
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
	public void load() {
		range = new XRange(loadShort(OBleft), loadShort(OBright));
		goLeft = !BitOp.test(loadByte(OBflags), 0);
	}
}
