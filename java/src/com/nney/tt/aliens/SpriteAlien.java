package com.nney.tt.aliens;

import com.nney.json.DataItem;
import com.nney.tt.AlienMovementServices;
import com.nney.tt.BitOp;
import com.nney.tt.LoadsFromSpriteDef;
import com.nney.tt.geom.Box;

public class SpriteAlien extends Alien implements LoadsFromSpriteDef {
	private static final int FLAG_BEHIND = 6;
	private boolean behind;
	private Box behindBox;

	@Override
	public void init() {
		changeAnimation(0);
	}
	
	@Override
	public void load() {
		behind = !BitOp.test(loadByte(OBflags), FLAG_BEHIND);
	}

	@Override
	public void load(DataItem di) {
		if (di.fieldExists("box")) {
			DataItem diBox = di.requireField("box");
			behindBox = DataItemHelpers.loadBox(diBox);
		}
	}

	
	@Override
	public void move(AlienMovementServices world) {
		if (behind && behindBox!=null && world.collideWithPlayerDP(this.c, behindBox)) {
			world.playerBehind();
		}
	}

}
