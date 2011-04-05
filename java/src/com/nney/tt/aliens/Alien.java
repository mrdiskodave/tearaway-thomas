package com.nney.tt.aliens;

import com.nney.AlienDrawingServices;
import com.nney.AlienMovementServices;
import com.nney.AnimPlayer;
import com.nney.Bounds;
import com.nney.Sprite;
import com.nney.SpriteSet;
import com.nney.tt.geom.Coord;

public abstract class Alien {
	public Coord c = new Coord();
	public AnimPlayer animPlayer = new AnimPlayer();
	public Bounds b;
	private SpriteSet spriteSet;
	public byte[] srcData;
	
	protected static final int OBbase=9;
	protected static final int OBflags=9-OBbase;		// B
	protected static final int OBleft=10-OBbase;		// W
	protected static final int OBtop=12-OBbase;		// W
	protected static final int OBright=14-OBbase;	// W
	protected static final int OBbottom=16-OBbase;	// W
//	protected static final int OBaPC=18-OBbase;		// B
//	protected static final int OBaoffset=19-OBbase;	// B
//	protected static final int OBafrac=20-OBbase;	// B
	protected static final int OBstatus0=22-OBbase;	// B
	protected static final int OBstatus1=23-OBbase;    // B
	protected static final int OBstatus2=24-OBbase;    // B
	protected static final int OBstatus3=25-OBbase;    // B
	protected static final int OBstatus4=26-OBbase;    // B
	protected static final int OBstatus5=27-OBbase;    // B
	protected static final int OBstatus6=28-OBbase;    // B
	protected static final int OBstatus7=29-OBbase;    // B

	
	protected int loadShort(int x) {
		return (loadByte(x)<<8)+loadByte(x+1);
	}

	protected int loadByte(int x) {
		return (srcData[x] & 255);
	}
	

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
	
	public void hide() {
		animPlayer.changeAnimation(null);
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

	public void load() {
		
	}
}
