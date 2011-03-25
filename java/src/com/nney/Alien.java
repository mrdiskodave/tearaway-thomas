package com.nney;

public abstract class Alien {
	public Coord c = new Coord();
	public AnimPlayer animPlayer = new AnimPlayer();

	public void draw(World world) {
		draw(world, c);
	}

	protected void draw(World world, Coord c2) {
		animPlayer.next().draw(c2.x-world.screen.x, c2.y-world.screen.y);
	}

	abstract public void move(World world);
}
