package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class MapperMousePosition {
	private Coord pos;
	private Coord delta;
	private Coord last = new Coord();

	private Coord worldPos;
	private Coord worldBlockPos;
	private Coord worldBlockPosDelta;
	private Coord lastWorldBlockPos = new Coord();
	private final Box worldLimits;
	private final Pointer mouse;

	public MapperMousePosition(Pointer mouse, Box worldLimits) {
		this.mouse = mouse;
		this.worldLimits = worldLimits;
	}

	private void update2(Coord mouseInScreen, Coord mouseInWorld) {
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

	public void update(Coord screenPosition) {
		Coord mousePos = new Coord(mouse.getX(), mouse.getY());
		update2(mousePos, screenPosition.add2(mousePos));
	}

	public Coord setScreenPixels(Coord c) {
		Coord answer = screenPixels();
		mouse.set(c.x, c.y);
		return answer;
	}
}