package com.nney.tt.mapper;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;

public class SuperBatRecord implements BatRecord {
	private final Alien alien;

	public SuperBatRecord(Alien selectedAlien) {
		this.alien = selectedAlien;
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForSuperBat(getPosition()).inside(c);
	}

	@Override
	public void setPosition(Coord pos) {
		Coord delta = pos.sub2(getPosition());
		APS.moveProps(alien, delta);
	}

	@Override
	public Coord getPosition() {
		return alien.getLocation();
	}
}
