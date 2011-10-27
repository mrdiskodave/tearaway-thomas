package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.World;
import com.nney.tt.geom.Coord;

public class MapperMousePosition {
	private Coord pos;
	private Coord delta;
	private Coord last = new Coord();

	private Coord worldPos;
	private Coord worldBlockPos;
	private Coord worldBlockPosDelta;
	private Coord lastWorldBlockPos = new Coord();

	void update(Coord mouse, Coord scr) {
		pos = mouse.copy();
		
		delta = pos.sub2(last);
		last = pos.copy();
		
		worldPos = pos.add2(scr);
		World.WHOLE_MAP_BOUNDS_IN_PIXELS.constrain(worldPos);
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
