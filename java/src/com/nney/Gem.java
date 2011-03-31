package com.nney;

//public class Gem extends Alien {
//	private static final int[] WOBBLE = { 0,-1,-2,-3,-2,-1,0,1,2,3,2,1 };
//	private static final Anim ANIM_STANDING_PURPLE;
//	private static final Anim ANIM_STANDING_YELLOW;
//	
//	static {
//		AnimBuilder ab = new AnimBuilder();
//		ab.select("0pgem");
//		ANIM_STANDING_PURPLE = ab.next().build();
//		ab.select("0ygem");
//		ANIM_STANDING_YELLOW = ab.next().build();
//	}
//
//	public static void loadGraphics(FrameLoader fl) {
//		fl.loadAll(ANIM_STANDING_PURPLE, ANIM_STANDING_YELLOW);
//	}
//	
//	
//	
//	private final boolean wobble;
//	private int wobblePhase;
//
//	
//	public Gem(int x, int y, boolean wobble, boolean yellow) {
//		c.x = x;
//		c.y = y;
//		this.wobble = wobble;
//		assert WOBBLE.length==12;
//		animPlayer.changeAnimation(yellow ? ANIM_STANDING_YELLOW : ANIM_STANDING_PURPLE);
//	}
//
//	@Override
//	public void move(World world) {
//	}
//
//	
//	@Override
//	public void draw(World world) {
//		Coord c2 = new Coord(c);
//		
//		// this is what gem_render -> bob_gem does
//		c2.y -= 9;
//		c2.x += 8;
//		c2.y += 9;
//		
//		if (wobble) {
//			c2.y += WOBBLE[wobblePhase];
//			wobblePhase++;
//			wobblePhase%= WOBBLE.length;
//		}
//		super.draw(world, c2);
//	}
//}
