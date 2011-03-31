package com.nney;

public class Gem extends Alien {
	private static final int[] WOBBLE = { 0,-1,-2,-3,-2,-1,0,1,2,3,2,1 };
	
	
	private final boolean wobble;
	private int wobblePhase;

	
	public Gem(int x, int y, boolean wobble) {
		c.x = x;
		c.y = y;
		this.wobble = wobble;
		assert WOBBLE.length==12;
	}

	@Override
	public void draw(World world) {
		Coord c2 = new Coord(c);
		
		// this is what gem_render -> bob_gem does
		c2.y -= 9;
		c2.x += 8;
		c2.y += 9;
		
		if (wobble) {
			c2.y += WOBBLE[wobblePhase];
			wobblePhase++;
			wobblePhase%= WOBBLE.length;
		}
		super.draw(world, c2);
	}
}
