package com.nney.tt.mapper;

import java.lang.reflect.Field;

import com.nney.tt.Const;
import com.nney.tt.MapperServices;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.map.GameMap;

public class Mapper {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	private static final int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int showTimer;
	private int currentBlock;
	final private int blockCount;
	private BlockPalette bp;

	final private MapperGC mgc;
	final private Pointer mouse;
	final private Keyboard keyboard;
	private final MapperServices parent;
	private final GameMap gameMap;
	
	private UndoControler undoControler = new UndoControler();
	private ColorCycler colorCycler = new ColorCycler();
	
	private AlienTool alienTool = new AlienTool();
	private ChooserTool chooserTool = new ChooserTool();
	private DrawTool drawTool = new DrawTool();
	private EyeDropperTool eyeDropperTool = new EyeDropperTool();
	private HandTool handTool = new HandTool();

	private ToolSlot tool = new ToolSlot();

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, MapperServices parent, Pointer mouse, Keyboard keyboard, GraphicsContext gc,
			BlocksHolder blocksHolder, Font debugFont) {
		this.gameMap = gameMap;
		this.parent = parent;
		this.mouse = mouse;
		this.keyboard = keyboard;
		blockCount = blocksHolder.getBlockCount();
		mgc = new MapperGC(gc, debugFont);
		bp = new BlockPalette(colorCycler, mgc, blocksHolder);
		tool.change(drawTool);
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
		private EditConsolidator editConsolidator;

		@Override
		void start() {
			drawPos = null;
			editConsolidator = new EditConsolidator(gameMap);
		}
		
		@Override
		public void run() {
			drawBlockCursor();
			
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
				editConsolidator.setBlock(computeMousePos().copyAndDiv(Const.BLOCK_SIZE), currentBlock);
			}
			else {
				stop();
			}
			
			keyboardBlockChoiceAndShow();
		}
		
		@Override
		void stop() {
			undoControler.addUndo(editConsolidator.endEdit());
		}

		@Override
		String name() {
			return "draw";
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
			if (mouse.isDown(Pointer.KEY_LEFT)) {
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
			else {
				stop();
			}
		}
		
		@Override
		void stop() {
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
			drawBlockCursor();
			if (mouse.isDown(Pointer.KEY_LEFT)) {
				currentBlock = gameMap.getBlock(computeMousePos().copyAndDiv(Const.BLOCK_SIZE));
				showBlocks();
			}
			keyboardBlockChoiceAndShow();
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
		Tool isHoliday() {
			if (keyboard.isDown(Keyboard.KEY_SPACE)) {
				return handTool;
			}
			return null;
		}
		
		@Override
		void run() {
			if (mouse.isDown(Pointer.KEY_LEFT)) {
				Coord c = computeMousePos();
				selectedAlien = parent.findNearestAlien(c);
			}

			if (haveAlien()) {
				Coord sac = selectedAlien.c.copy();
				sac.sub(parent.getScreenPosition());
				mgc.drawSight(sac.x, sac.y, 7, colorCycler.process(0xff00ffff));

				Field[] fs = selectedAlien.getClass().getFields();
				for (Field f : fs) {
					AlienProp z = f.getAnnotation(AlienProp.class);
					if (z!=null) {
						if (f.getType()==Box.class) {
							
							try {
								Box box = (Box) f.get(selectedAlien);
								box = box.copy();
								Coord c = parent.getScreenPosition();
								c = c.copy();
								c.mul(-1);
								box.move(c);
								mgc.drawTransBox(box.left, box.top, box.width(), box.height(), 0xffff0000, 0x80000000);
							}
							catch (IllegalArgumentException e) {
								throw new RuntimeException(e);
							}
							catch (IllegalAccessException e) {
								throw new RuntimeException(e);
							}
						}
						
					}
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
		void stop() {}
		void run() {};
		Tool isHoliday() { return null; }
	}
	
		
	
	public void run() {
		colorCycler.advance();
		
		if (!tool.get().ownScreen()) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			parent.drawMap();
			parent.mapperDrawAliens();
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
			tool.change(eyeDropperTool);
			return;
		case Keyboard.KEY_H:
			tool.change(handTool);
			return;
		case Keyboard.KEY_D:
			tool.change(drawTool);
			return;
		case Keyboard.KEY_C:
			tool.change(chooserTool);
			return;
		case Keyboard.KEY_A:
			tool.change(alienTool);
			return;
		}
		
		sayIt(tool.get().name());
		tool.get().run();
		
		if (!tool.get().ownScreen()) {
			undoRedo();
		}
	}






	private void drawBlockCursor() {
		Coord mousePos = computeMousePos();
		{
			Coord box = mousePos.copy();
			box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
			box.sub(parent.getScreenPosition());
			mgc.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, colorCycler.process(COL_CURRENT_BLOCK));
		}
	}






	private void sayIt(String string) {
		mgc.drawText(10, 10, 0xffffff, string);
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



	private void keyboardBlockChoiceAndShow() {
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
