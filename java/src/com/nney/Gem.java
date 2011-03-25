package com.nney;

public class Gem extends Alien {
	static private Anim standingGem;
	static private int[] WOBBLE = { 0,-1,-2,-3,-2,-1,0,1,2,3,2,1 };
	private int wobblePhase;
	private final boolean wobble;

	public Gem(int x, int y, boolean wobble) {
		c.x = x;
		c.y = y;
		this.wobble = wobble;
		assert WOBBLE.length==12;
	}

	@Override
	public void move(World world) {
		animPlayer.changeAnimation(standingGem);
	}

	static public void loadGraphics(AnimBuilder ab) {
		ab.select("0pgem");
		standingGem = ab.next().build();
	}
	
	@Override
	public void draw(World world) {
		Coord c2 = new Coord(c);
		
		c2.y -= 9;
		c2.x += 8;
		c2.y += 9;
		
		c2.x -= 1;
		c2.y -= 1;
		
		if (wobble) {
			c2.y += WOBBLE[wobblePhase];
			wobblePhase++;
			wobblePhase%= WOBBLE.length;
		}
		super.draw(world, c2);
	}
}
