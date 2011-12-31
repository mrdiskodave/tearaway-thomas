package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class MapperMousePosition {
	private Coord pos;
	private Coord delta;
	private Coord last = new Coord();

	private Coord worldPos;
	private Coord worldBlockPos;
	private Coord worldBlockPosDelta;
	private Coord lastWorldBlockPos = new Coord();
	private final Box worldLimits;

	public MapperMousePosition(Box worldLimits) {
		this.worldLimits = worldLimits;
	}

	public void update(Coord mouseInScreen, Coord mouseInWorld) {
		pos = mouseInScreen.copy();
		delta = pos.sub2(last);
		last = pos.copy();

		worldPos = mouseInWorld.copy();
		worldLimits.constrain(worldPos);
		worldBlockPos = worldPos.asr2(Const.BLOCK_SHIFT);
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