package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.Const;
import com.nney.tt.MapperServices;
import com.nney.tt.World;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.map.GameMap;

public class Mapper {

	private static final int COL_BACKGROUND = 0xff0080ff;
	private int showTimer;
	private int currentBlock;

	final private int blockCount;
	final private MapperGC mapperGC;
	final private GraphicsContext gc;
	final private Pointer mouse;
	final private Keyboard keyboard;
	private final MapperServices parent;
	private final Font debugFont;
	private final GameMap gameMap;
	private UndoControler undoControler = new UndoControler();
	private DrawingTool drawingTool;
	private BlockPalette bp;
	private MapperColors mc = new MapperColors();
	private Tool mode = new DrawTool();
	
	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, MapperServices parent, Pointer mouse, Keyboard keyboard, GraphicsContext gc,
			BlocksHolder blocksHolder, Font debugFont) {
		this.gameMap = gameMap;
		this.parent = parent;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.gc = gc;
		this.debugFont = debugFont;
		this.drawingTool = new DrawingTool(gameMap);
		blockCount = blocksHolder.getBlockCount();
		mapperGC = new MapperGC(gc, debugFont);
		bp = new BlockPalette(mc, mapperGC, blocksHolder);
		
		
	}

	private final class ChooserTool extends Tool {
		@Override
		boolean ownScreen() {
			return true;
		}

		@Override
		String name() {
			return "chooser";
		}

		@Override
		void run() {
			blockChoosingMode();
			showBlocks();
		}
	}

	private final class DrawTool extends Tool {
		private Coord drawPos;
		
		@Override
		void start() {
			drawPos = null;
		}

		@Override
		public void run() {
			if (keyboard.isDown(Keyboard.KEY_LCONTROL)) {
				showBlocks();
				if (drawPos != null) {
					Coord oldBlock = drawPos.copy();
					oldBlock.div(Const.BLOCK_SIZE);
					Coord newBlock = computeMousePos();
					newBlock.div(Const.BLOCK_SIZE);
					newBlock.sub(oldBlock);
					changeCurrentBlock(newBlock.x, newBlock.y);
				}
				drawPos = computeMousePos();
			}
			else {
				drawPos = null;
			}
			// Drawing with the left button
			if (mouse.isDown(Pointer.KEY_LEFT)) {
				drawingTool.setBlock(computeMousePos().copyAndDiv(Const.BLOCK_SIZE), currentBlock);
			}
			else {
				undoControler.addUndo(drawingTool.endEdit());
			}
			keyboardBlockChoiceShown();
		}

		@Override
		String name() {
			return "track";
		}
	}

	private final class HandTool extends Tool {
		Coord dragPos;
		
		@Override
		void start() {
			dragPos = computeMousePos();
		}

		@Override
		public void run() {
			if (dragPos !=null && mouse.isDown(Pointer.KEY_LEFT)) {
				Coord delta = dragPos.copy();
				delta.sub(computeMousePos());
				if (keyboard.isDown(Keyboard.KEY_LSHIFT)) {
					delta.mul(2);
				}
				if (keyboard.isDown(Keyboard.KEY_LCONTROL)) {
					delta.mul(4);
				}
				parent.moveScreen(delta);
			}
			dragPos = computeMousePos();
		}

		@Override
		String name() {
			return "hand";
		}
	}

	private final class EyeDropperTool extends Tool {
		@Override
		String name() {
			return "eyedropper";
		}

		@Override
		void run() {
			showBlocks();
			if (mouse.isDown(Pointer.KEY_LEFT)) {
				currentBlock = gameMap.getBlock(computeMousePos().copyAndDiv(Const.BLOCK_SIZE));
			}
			keyboardBlockChoiceShown();
		}
	}
	
	private final class AlienTool extends Tool {
		Alien selectedAlien;
		
		boolean haveAlien() {
			if (selectedAlien!=null && !selectedAlien.remove) {
				return true;
			}
			selectedAlien = null;
			return false;
		}
		
		@Override
		void run() {
			if (mouse.justPressed(Pointer.KEY_LEFT)) {
				Coord c = computeMousePos();
				selectedAlien = parent.findClosestAlien(c);
				if (haveAlien()) {
					
				}
				
				
			}
		}
		
		@Override
		String name() {
			return "alien";
		}
	}
	

	abstract class Tool {
		abstract String name();
		void start() {}
		boolean ownScreen() { return false; }
		void run() {};
	}
	
		
	
	public void run() {
		mc.advance();
		
		if (!mode.ownScreen()) {
			gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), COL_BACKGROUND);
			parent.drawMap();
			parent.mapperDrawAliens();

			Coord mousePos = computeMousePos();
			{
				Coord box = mousePos.copy();
				box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
				box.sub(parent.getScreenPosition());
				mapperGC.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mc.currentBlock());
			}
	
	
			if (showTimer != 0) {
				showTimer--;
				bp.showSmallPalette(currentBlock);
			}
		}

		
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_TAB:
			parent.quitMapper(computeMousePos());
			return;
		case Keyboard.KEY_I:
			changeMode(new EyeDropperTool());
			return;
		case Keyboard.KEY_H:
			changeMode(new HandTool());
			return;
		case Keyboard.KEY_D:
			changeMode(new DrawTool());
			return;
		case Keyboard.KEY_C:
			changeMode(new ChooserTool());
			return;
		case Keyboard.KEY_A:
			changeMode(new AlienTool());
			return;
		}
		
		sayIt(mode.name());
		mode.run();
		
		if (!mode.ownScreen()) {
			undoRedo();
		}

	}






	private void sayIt(String string) {
		int x = 10;
		int y = 10;
		debugFont.draw(x, y, 0xffffff, 0, string);
	}



	private void changeMode(Tool mm) {
//		mode.stop();
		mode = mm;
		mode.start();
	}



	private void undoRedo() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_U:
			undoControler.undo();
			break;
		case Keyboard.KEY_R:
			undoControler.redo();
			break;
		}
	}



	private void keyboardBlockChoiceShown() {
		if (keyboardBlockChoice()) {
			showBlocks();
		}
	}

	private void showBlocks() {
		showTimer = 100;
	}

	private boolean keyboardBlockChoice() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_0:
			currentBlock = 0;
			return true;
		case Keyboard.KEY_UP:
			changeCurrentBlock(0, -1);
			return true;
		case Keyboard.KEY_DOWN:
			changeCurrentBlock(0, 1);
			return true;
		case Keyboard.KEY_LEFT:
			changeCurrentBlock(-1, 0);
			return true;
		case Keyboard.KEY_RIGHT:
			changeCurrentBlock(1, 0);
			return true;
		}
		return false;
	}


	private Coord computeMousePos() {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		mp.add(parent.getScreenPosition());
		return mp;
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	

	private void changeCurrentBlock(int dx, int dy) {
		int delta = bp.getPaletteDelta(dx, dy);
		int b = delta +  currentBlock;
		if (b < 0) {
			b += blockCount;
		}
		if (b >= blockCount) {
			b -= blockCount;
		}
		currentBlock = b;
	}
	
	private void blockChoosingMode() {
		keyboardBlockChoice();
		int mx = mouse.getX();
		int my = mouse.getY();

		// System.out.println(String.format("%d,%d", mx, my));
		// drawSight(mx, my, 20, 0xff0000);

		int hoverBlock = bp.showBigPalette(currentBlock, mx, my);
		if (mouse.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			currentBlock = hoverBlock;
		}
	}


}
