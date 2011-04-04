package com.nney;

public class ArrowAlien extends Alien {
	private int leftLimit;
	private int rightLimit;
	private int topLimit;
	private int bottomLimit;
	private boolean colide;

	@Override
	public void load() {
		leftLimit = loadShort(OBleft);
		rightLimit = loadShort(OBright);
		topLimit = loadShort(OBtop);
		bottomLimit = loadShort(OBbottom);
	}
	
	@Override
	public void move(AlienMovementServices world) {
		Coord c = world.getPlayerPosition();
		colide = c.x>=leftLimit && c.x<=rightLimit && c.y>=topLimit && c.y<=bottomLimit;
	}
	
	@Override
	public void draw(AlienDrawingServices world) {
		world.debugText(c, colide ? "**YES**" : "no");
	}
}
