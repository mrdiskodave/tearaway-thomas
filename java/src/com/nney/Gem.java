package com.nney;

public class Gem extends Alien {
	static final private int[] WOBBLE = { 0,-1,-2,-3,-2,-1,0,1,2,3,2,1 };
	private static Anim standingPurpleGem;
	private static Anim standingYellowGem;
	private int wobblePhase;
	private final boolean wobble;

	static {
		AnimBuilder ab = new AnimBuilder();
		ab.select("0pgem");
		standingPurpleGem = ab.next().build();
		ab.select("0ygem");
		standingYellowGem = ab.next().build();
	}
	
	public Gem(int x, int y, boolean wobble, boolean yellow) {
		c.x = x;
		c.y = y;
		this.wobble = wobble;
		assert WOBBLE.length==12;
		animPlayer.changeAnimation(yellow ? standingYellowGem : standingPurpleGem);
	}

	@Override
	public void move(World world) {
	}

	public static void loadGraphics(FrameLoader fl) {
		fl.loadAll(standingPurpleGem, standingYellowGem);
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
