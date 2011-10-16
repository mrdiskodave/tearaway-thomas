package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;

public class MapperMousePosition {
	private static final double FULL_CIRCLE = 2*Math.PI;

	
	private Coord snap;
	
	private Coord pos;
	private Coord delta;
	private Coord last = new Coord();

	private Coord worldPos;
	private Coord worldBlockPos;
	private Coord worldBlockPosDelta;
	private Coord lastWorldBlockPos = new Coord();
	private double spokeSize;
	
	
	void startSnap(int spokes) {
		if (spokes!=0) {
			spokeSize = FULL_CIRCLE/spokes;
			snap = pos.copy();
		}
	}
	
	void stopSnap() {
		snap = null;
	}
	
	void update(Coord mouse, Coord scr) {
		pos = mouse.copy();
		
		if (snap!=null) {
			Coord d = pos.sub2(snap);
			double length = Math.sqrt(d.squareOfLength());
			double angle = Math.atan2(d.y, d.x);
			angle /= spokeSize;
			angle = Math.round(angle);
			angle *= spokeSize;
			long y = Math.round(Math.sin(angle)*length);
			long x = Math.round(Math.cos(angle)*length);
			Coord e = new Coord((int)x, (int)y);
			pos = snap.add2(e);
//			System.out.println("relative: "+d+" -> "+e + " snap:"+snap + " pos:"+pos);
		}
		
		delta = pos.sub2(last);
		last = pos.copy();
		
		worldPos = pos.add2(scr);
		worldBlockPos = worldPos.div2(Const.BLOCK_SIZE);
		worldBlockPosDelta = worldBlockPos.sub2(lastWorldBlockPos);
		lastWorldBlockPos = worldBlockPos.copy();
	}
	
	
	public Coord screenPixels() {
		return pos.copy();
	}

	public Coord pixelsDelta() {
		return delta.copy();
	}
	
	public Coord worldPixels() {
		return worldPos.copy();
	}

	public Coord worldBlocks() {
		return worldBlockPos.copy();
	}

	public Coord worldBlocksDelta() {
		return worldBlockPosDelta.copy();
	}

	
}
