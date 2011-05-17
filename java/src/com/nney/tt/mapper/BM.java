package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

/**
 * Bat Manager. "bats" (as in sports bats) throughout because "control point" is
 * such a mouthful.
 */
public abstract class BM {

	abstract void sendBat(Coord alien, BatTarget rt);

	void takeMovement(int what, Coord where) {
	}
}