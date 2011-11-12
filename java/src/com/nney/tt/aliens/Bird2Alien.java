package com.nney.tt.aliens;

import com.nney.tt.aliens.Wave.Result;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

public class Bird2Alien extends Alien {
	@PropAnn(doc = "Where are we?", label = "location")
	public Coord c1 = new Coord();

	@PropAnn(doc = "The horizontal span in which we move.", label = "range")
	public XRange range;

	@PropAnn(name = "Facing", doc = "Do we face left or right?", xtraDef = "leftright", label = "goLeft")
	public boolean goLeft;

	@PropAnn(doc="How fast do we move?", max=400)
	public int speed = 200;
	
	private Coord c2;

	private String animName;

	private Box box;
	
	@Override
	public void onLoaded() {
		box = anims.box();
	}
	
	void generateInternalStateFromFrameNumber() {
		int phase = c1.x - range.left;
		int span = range.width();
		if (goLeft) {
			phase = span*2 - phase;
		}
		Result r = Wave.z(span, 0, Math2.fracMult(srv.getFrameNumber(), speed, 100), phase);
		c2 = new Coord(range.left+r.pos, c1.y);
		animName = Anims.directionalAnimName(r.goLeft(), "");
	}

	@Override
	public void update() {
		generateInternalStateFromFrameNumber();
		changeAnimation(animName);
		Sprite s = nextFrame();
		srv.drawSprite(c2, s);
		freezeBounds = box.add2(c2);
		if (srv.collideAlienWithPlayerHiRes(c2, s)) {
			srv.headBounce(this, s);
		}
	}

	@Override
	public void resetTo(Coord p) {
		c1 = p;
		range = new XRange(0, 0);
		range.around(c1.x, 50);
		range.add(25);
	}

	@Override
	public Anim mapperAnim() {
		generateInternalStateFromFrameNumber();
		return anims.find(animName);
	}

	@Override
	public Coord getLocation() {
		generateInternalStateFromFrameNumber();
		return c2;
	}
}
