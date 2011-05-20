package com.nney.tt.aliens;

import com.nney.tt.AlienServices;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;

public abstract class Alien {
	@AlienProp(name = "Location", doc = "Where are we?", xtraDef = "location")
	public Coord c = new Coord();

	protected AnimPlayer animPlayer = new AnimPlayer();
	private Anims spriteSet;
	public byte[] legacyData;
	public boolean remove;
	public int depth = DEPTH_BACKGROUND;

	public static final int DEPTH_MAP = 0;
	public static final int DEPTH_BACKGROUND = 1;
	public static final int DEPTH_FOREGROUND = 2;
	public static final int DEPTH_MAX = 3;

	public void resetTo(Coord p) {
		c = p;
	}

	public Box freezeBounds;
	public AlienServices srv;

	protected static final int OBbase = 9;
	protected static final int OBflags = 9 - OBbase; // B
	protected static final int OBleft = 10 - OBbase; // W
	protected static final int OBtop = 12 - OBbase; // W
	protected static final int OBright = 14 - OBbase; // W
	protected static final int OBbottom = 16 - OBbase; // W
	// protected static final int OBaPC=18-OBbase; // B
	// protected static final int OBaoffset=19-OBbase; // B
	// protected static final int OBafrac=20-OBbase; // B
	protected static final int OBstatus0 = 22 - OBbase; // B
	protected static final int OBstatus1 = 23 - OBbase; // B
	protected static final int OBstatus2 = 24 - OBbase; // B
	protected static final int OBstatus3 = 25 - OBbase; // B
	protected static final int OBstatus4 = 26 - OBbase; // B
	protected static final int OBstatus5 = 27 - OBbase; // B
	protected static final int OBstatus6 = 28 - OBbase; // B
	protected static final int OBstatus7 = 29 - OBbase; // B

	// abstract public void reset();
	public void onPropUpdate() {
	}

	protected int loadShort(int x) {
		return (loadByte(x) << 8) + loadByte(x + 1);
	}

	protected int loadByte(int x) {
		return (legacyData[x] & 255);
	}

	protected void changeAnimation(String name) {
		assert spriteSet != null;
		assert name != null;
		changeAnimation(spriteSet.find(name));
	}

	protected void changeAnimation(Anim anim) {
		assert anim != null;
		animPlayer.changeAnimation(anim);
	}

	protected void changeAnimation(int name) {
		assert spriteSet != null;
		animPlayer.changeAnimation(spriteSet.find(name));
	}

	protected void hide() {
		animPlayer.changeAnimation(null);
	}

	protected Sprite nextFrame() {
		return animPlayer.next();
	}

	protected Sprite sameFrame() {
		return animPlayer.current();
	}

	public void connectAnims(Anims s) {
		spriteSet = s;
	}

	protected void draw(Coord c2) {
		Sprite s = nextFrame();
		if (s != null) {
			srv.drawSprite(c2, s);
		}
	}

	public void visualReset() {
	}

	public void loadFromLegacyData() {

	}

	abstract public void update();

	public void mapperUpdate() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
	}

	public void done() {
		remove = true;
	}

	protected Box spriteBounds(Sprite s) {
		return Box.fromTopLeftAndSize(c.x - s.handleX, c.y - s.handleY, s.w, s.h);
	}
}
