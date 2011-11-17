package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.utils.Math2;

public abstract class LeftRightAlien extends AlienWithLocation {
	@PropAnn(doc = "The horizontal span in which we move.", label = "range")
	public XRange range;

	@PropAnn(name = "Facing", doc = "Do we face left or right?", xtraDef = "leftright", label = "goLeft")
	public boolean goLeft;

	protected int movingFright;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		range = new XRange(0, 0);
		range.around(c.x, 50);
		range.add(25);
	}

	@Override
	public Anim mapperAnim() {
		return anims.find(goLeft ? "left" : "right");
	}

	boolean moveLeftRight(int speed) {
		if (movingFright!=0) {
			movingFright--;
			changeAnimation("movingFright");
		}
		else {
			changeAnimation(Anims.directionalAnimName(goLeft, ""));
		}
		if (!goLeft) {
			c.x += speed;
			if (c.x > range.right) {
				goLeft = true;
				return true;
			}
		}
		else {
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
