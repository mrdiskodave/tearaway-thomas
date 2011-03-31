package com.nney;

public abstract class Alien {
	public Coord c = new Coord();
	public AnimPlayer animPlayer = new AnimPlayer();
	private SpriteSet ss;

	public void connectSpriteSet(SpriteSet s) {
		ss = s;
		animPlayer.changeAnimation(ss.find(0));
	}

	public void changeAnimation(String name) {
		assert ss != null;
		assert name != null;
		animPlayer.changeAnimation(ss.find(name));
	}

	public void draw(World world) {
		draw(world, c);
	}

	protected void draw(World world, Coord c2) {
		world.drawAlien(c2, animPlayer.next());
	}

	public void move(World world) {
	}

	public void init() {
	}
}
