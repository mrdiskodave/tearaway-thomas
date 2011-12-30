package com.nney.tt.aliens;

import com.nney.tt.AlienInfo;
import com.nney.tt.AlienServices;
import com.nney.tt.Bounded;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.HasProps;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;

/**
 * All the non-player things in the game are called "aliens" for legacy reasons.
 * It's because the first game I wrote was set in space - it had "aliens" - and
 * the name stuck.
 */
public abstract class Alien implements HasProps, Bounded {
	enum LifeCycle {
		INSTANTIATED, ATTACH, READY, UNLOAD
	}

	private LifeCycle lifeCycle = LifeCycle.INSTANTIATED;

	public AlienInfo alienInfo;
	protected AnimPlayer animPlayer = new AnimPlayer();
	public Anims anims;
	public byte[] legacyData;
	public boolean remove;
	public int depth = DEPTH_ALIENS;

	public static final int DEPTH_BG_SCENARY = 0;
	public static final int DEPTH_LIFTS = 1;
	public static final int DEPTH_COLLECTABLES = 2;
	public static final int DEPTH_ALIENS = 3;
	// <-- player!
	public static final int DEPTH_FG_SCENARY = 4;
	public static final int DEPTH_MAX = 5;

	public Box freezeBounds;

	@Override
	public Box getBounds() {
		return freezeBounds;
	}

	public AlienServices srv;

	protected static final int OBbase = 8;

	protected static final int OBtype = 0; // B
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

	protected static final int OBFinvis = 5;

	protected int loadShort(int x) {
		return (loadByte(x) << 8) + loadByte(x + 1);
	}

	protected int loadByte(int x) {
		return (legacyData[x] & 255);
	}

	protected void changeAnimation(String name) {
		assert anims != null;
		assert name != null;
		animPlayer.changeAnimation(anims.find(name));
	}

	protected void changeAnimation(int name) {
		assert anims != null;
		animPlayer.changeAnimation(anims.find(name));
	}

	protected void setAnimation(String name) {
		assert anims != null;
		assert name != null;
		animPlayer.setAnimation(anims.find(name));
	}

	protected void setAnimation(int name) {
		assert anims != null;
		animPlayer.setAnimation(anims.find(name));
	}

	protected Box spriteBounds(Sprite s) {
		return s.getBounds().add2(getLocation());
	}

	protected Box boxAroundUs(int size) {
		return Box.around(getLocation(), size);
	}

	protected Sprite nextFrame() {
		return animPlayer.nextFrame();
	}

	protected Sprite sameFrame() {
		return animPlayer.currentFrame();
	}

	protected Sprite firstFrame() {
		return anims.find(0).firstSprite();
	}

	protected void draw(Coord c2) {
		Sprite s = nextFrame();
		if (s != null) {
			srv.drawSprite(c2, s);
		}
	}

	public void onLoaded() {
	}

	public void loadFromLegacyData() {

	}

	public Anim mapperAnim() {
		return anims.find(0);
	}

	public void mapperUpdate() {
		Coord c = getLocation();
		if (anims != null) {
			Sprite s = mapperAnim().firstSprite();
			srv.drawSprite(c, s);
			freezeBounds = s.getBounds().add2(c);
		}
		else {
			srv.drawDebugText(c, alienInfo.name);
		}
	}

	abstract public void update();

	abstract public void resetTo(Coord p);

	abstract public Coord getLocation();

	@Override
	public void onPropUpdate() {
	}

	protected void animateDrawAndStun(Coord c2) {
		Sprite s = nextFrame();
		srv.drawSprite(c2, s);
		if (srv.collideAlienWithPlayerHiRes(c2, s)) {
			srv.getThePlayer().stun();
		}
	}

	public void attach(AlienInfo alienInfo2, AlienServices srv2) {
		fromTo(LifeCycle.INSTANTIATED, LifeCycle.ATTACH);
		alienInfo = alienInfo2;
		srv = srv2;
	}

	public void connect(AnimsPool ap) {
		fromTo(LifeCycle.ATTACH, LifeCycle.READY);
		String a = alienInfo.animsName();
		if (a != null) {
			anims = ap.expect(a);
		}
		onLoaded();
		onPropUpdate();
	}

	public void connect(Alien src) {
		fromTo(LifeCycle.ATTACH, LifeCycle.READY);
		anims = src.anims;
		onLoaded();
		onPropUpdate();
	}

	public void done() {
		fromTo(LifeCycle.READY, LifeCycle.UNLOAD);
		remove = true;
	}

	public void reinstate() {
		fromTo(LifeCycle.UNLOAD, LifeCycle.READY);
		remove = false;
	}

	private void fromTo(LifeCycle pre, LifeCycle post) {
		assert lifeCycle == pre;
		lifeCycle = post;
	}

	void pseudoAlienUpdate() {
		freezeBounds = Box.around(getLocation());
	}
}
