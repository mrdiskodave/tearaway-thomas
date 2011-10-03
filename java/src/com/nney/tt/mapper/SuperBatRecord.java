package com.nney.tt.mapper;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;

public class SuperBatRecord implements BatRecord {
	private final Coord where;
	private final Alien alien;

	public SuperBatRecord(Alien selectedAlien) {
		this.alien = selectedAlien;
		this.where = alien.getLocation().copy();
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForSuperBat(where).inside(c);
	}

	@Override
	public void press(Coord delta) {
		APS.moveProps(alien, delta);
	}
}
