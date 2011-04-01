package com.nney;

public class Gem extends Alien {
	private static final int[] WOBBLE = { 0,-1,-2,-3,-2,-1,0,1,2,3,2,1 };
	
	private final boolean wobble;
	private int wobblePhase = -1;

	
	public Gem(int x, int y, boolean wobble) {
		c.x = x;
		c.y = y;
		this.wobble = wobble;
		assert WOBBLE.length==12;
	}

	@Override
	public void draw(AlienDrawingServices ads) {
		if (wobblePhase<0) {
			// could we do this earlier?
			wobblePhase = ads.randomness(WOBBLE.length);
		}
		
		Coord c2 = new Coord(c);
		
		// this is what gem_render -> bob_gem does
		c2.x += 8;
		
		if (wobble) {
			c2.y += WOBBLE[wobblePhase];
			wobblePhase++;
			wobblePhase%= WOBBLE.length;
		}
		super.draw(ads, c2);
	}
	
	@Override
	public void init() {
		changeAnimation(0);
	}
}
