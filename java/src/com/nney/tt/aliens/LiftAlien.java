package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public class LiftAlien extends Alien {
	private Box box;
	private Coord lc;
	private int lastMove;
	
	@Override
	public void load() {
		box = new Box(loadShort(OBleft), loadShort(OBtop), loadShort(OBright), loadShort(OBbottom));
	}

	static int sine(int idx) {
		int maxInput = 1024;
		int maxOutput = 1024;
		idx &= maxInput-1;
		double angle = (2*Math.PI*idx)/maxInput;
		return (int) (Math.sin(angle)*maxOutput);
	}
	
	@Override
	public void update() {
		moveIt();
		
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		
		Player p = srv.getThePlayer();
		if (!p.isStunned()) {
			if (p.lift==null) {
				int landOn = c.y-1;
				boolean horizOverlap = p.c.x>=c.x && p.c.x<=c.x+44;
				boolean verticalCrossing = p.lc.y<landOn && p.c.y>=landOn; 
				if (horizOverlap && verticalCrossing) {
					p.lift = this;
					p.c.y = landOn;
					p.reset();
				}
			}
		}
	}

	private void moveIt() {
		int f = srv.getFrameNumber();
		if (f!=lastMove) {
			lastMove = f;
			lc = c.copy();
			setPosition();
		}
	}
	
	public void movePlayer() {
		moveIt();
		
		Player p = srv.getThePlayer();
		Coord z = c.copy();
		z.sub(lc);
		p.c.add(z);
	}

	private void setPosition() {
		int angle = srv.getFrameNumber()*8;
		Coord origin = new Coord((box.left + box.right) / 2, box.top);
		int spin = sine(angle)/4+256;
		int xo = sine(spin+256)*box.width();
		int yo = sine(spin)*box.height();
		xo /= 1024*2;
		yo /= 1024;
		c.x = origin.x+xo;
		c.y = origin.y+yo;
	}

}
