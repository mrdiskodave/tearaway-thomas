package com.nney.tt.aliens;

import com.nney.tt.aliens.Wave.Result;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;

public class Bird2Alien extends AlienWithLocation {
	@PropAnn(doc = "The horizontal span in which we move.", label = "range")
	public XRange range;

	@PropAnn(name = "Facing", doc = "Do we face left or right?", xtraDef = "leftright", label = "goLeft")
	public boolean goLeft;

	private int lastMoveFrmNum;

	private Coord c2;

	private String animName;
	
	void moveOnce() {
		int chngNum = srv.getChangingNumber();
		if (chngNum != lastMoveFrmNum) {
			lastMoveFrmNum = chngNum;
			Result r = ourResult();
			c2 = new Coord(range.left+r.pos, c.y);
			animName = Anims.directionalAnimName(r.goLeft(), "");
		}
	}

	@Override
	public void update() {
		moveOnce();
		changeAnimation(animName);
		Sprite s = nextFrame();
		srv.drawSprite(c2, s);
		if (srv.collideAlienWithPlayerHiRes(c2, s)) {
			srv.headBounce(this, s);
		}
	}

	private Result ourResult() {
		int phase = c.x - range.left;
		int span = range.width();
		if (goLeft) {
			phase = span*2 - phase;
		}
		return Wave.z(span, 0, srv.getFrameNumber()*2, phase);
	}

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		range = new XRange(0, 0);
		range.around(c.x, 50);
		range.add(25);
	}

	@Override
	public Anim mapperAnim() {
		moveOnce();
		return anims.find(animName);
	}

	@Override
	public Coord getLocation() {
		moveOnce();
		Coord answer = c2;
		System.out.println("BIRD@ "+answer);
		return answer;
	}
}
