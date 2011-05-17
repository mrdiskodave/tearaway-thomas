package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

/**
 * Bat Manager. I'm typing "bats" (as in "sports bats") throughout because
 * "control point" is such a mouthful.
 */
public abstract class BM {
	abstract void createBats(Coord alien, BatTarget rt);
	abstract void takeBatMovement(int what, Coord where);
}