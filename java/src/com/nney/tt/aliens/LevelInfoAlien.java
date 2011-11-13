package com.nney.tt.aliens;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

public class LevelInfoAlien extends Alien {
	@PropAnn(doc = "How many gems must be collected before the exit opens?")
	public int gemsNeeded;

	@PropAnn(doc = "How many seconds is the player allowed to complete the level?")
	public int timeGiven;
	
	@PropAnn(doc = "What horizon sits behind the level?")
	public int horizon;
	
	@PropAnn(doc = "What is the title of this level?")
	public String title;
	
	@Override
	public void update() {
		pseudoAlienUpdate();
	}

	@Override
	public void resetTo(Coord p) {
		// not needed
	}

	@Override
	public Coord getLocation() {
		int x = Const.BLOCK_SIZE/2;
		return new Coord(x, x);
	}
}
