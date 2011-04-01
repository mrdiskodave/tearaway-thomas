package com.nney;

public abstract class Alien {
	public Coord c = new Coord();
	public AnimPlayer animPlayer = new AnimPlayer();
	private SpriteSet spriteSet;

	public void connectSpriteSet(SpriteSet s) {
		spriteSet = s;
	}

	public void changeAnimation(String name) {
		assert spriteSet != null;
		assert name != null;
		animPlayer.changeAnimation(spriteSet.find(name));
	}

	public void changeAnimation(int name) {
		assert spriteSet != null;
		animPlayer.changeAnimation(spriteSet.find(name));
	}

	public void draw(AlienDrawingServices world) {
		draw(world, c);
	}

	protected void draw(AlienDrawingServices world, Coord c2) {
		Sprite s = animPlayer.next();
		if (s==null) return;
		world.drawSprite(c2, s);
	}

	public void move(AlienMovementServices world) {
	}

	public void init() {
	}
}
