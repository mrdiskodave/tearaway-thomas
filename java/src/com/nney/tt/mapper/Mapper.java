package com.nney.tt.mapper;

import java.util.Map.Entry;

import com.nney.tt.Const;
import com.nney.tt.MapperServices;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.UnifiedKeyTester;
import com.nney.tt.map.GameMap;

public class Mapper implements PenServices {
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
	final private UnifiedKeyTester ukt;

	// private AlienTool alienTool = new AlienTool();
	private Tool chooserTool = new ChooserTool();
	private Tool drawTool = new GeneralTool(Cursor.BLOCK, "draw", new BlockTrackingPen(), new DrawingPen());
	private Tool eyeDropperTool = new GeneralTool(Cursor.BLOCK, "eyeDropper", new EyeDropperPen());
	private Tool handTool = new GeneralTool(Cursor.NONE, "hand", new HandLard());

	private Tool tool;
	private Tool otherTool;

	private int keyThatSustainsTheOtherTool;

	private EditConsolidator edit;

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, MapperServices parent, Pointer mouse, Keyboard keyboard, GraphicsContext gc,
			BlocksHolder blocksHolder, Font debugFont) {
		this.gameMap = gameMap;
		this.parent = parent;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.ukt = new UnifiedKeyTester(mouse, keyboard);
		blockCount = blocksHolder.getBlockCount();
		mgc = new MapperGC(gc, debugFont);
		bp = new BlockPalette(colorCycler, mgc, blocksHolder);
		tool = drawTool;
	}

	private final class ChooserTool extends Tool {
		@Override
		boolean ownScreen() {
			return true;
		}

		@Override
		void run() {
			blockChoosingMode();
			showBlocks();
		}
	}

	private final class GeneralTool extends Tool {
		private final Pen[] pens;
		private final String name;
		private final Cursor cursor;

		GeneralTool(Cursor cursor, String name, Pen... pens) {
			this.cursor = cursor;
			this.name = name;
			this.pens = pens;
		}

		@Override
		public void run() {
			if (isFree()) {
				for (Entry<Integer, Tool> e: nest.entrySet()) {
					if (ukt.isDown(e.getKey())) {
						pushTool(e.getKey(), e.getValue());
					}
				}
			}
			if (cursor == Cursor.BLOCK) {
				drawBlockCursor();
			}
			for (Pen pen : pens) {
				pen.srv = Mapper.this;
				
				Coord m = computeMousePos(pen.usesWorldCoords());
				boolean pressed = ukt.isDown(pen.key());
				if (pen.active) {
					if (pressed) {
						pen.stroke(m.copy());
					}
					else {
						pen.up(m.copy());
						pen.active = false;
						lessBusy();
					}
				}
				else {
					if (pressed) {
						pen.down(m.copy());
						pen.active = true;
						moreBusy();
					}
				}
				
				pen.always();
			}
		}

		@Override
		String name() {
			return name;
		}
	}

	// private final class AlienTool extends Tool {
	// Alien selectedAlien;
	//
	// boolean haveAlien() {
	// if (selectedAlien!=null && !selectedAlien.remove) {
	// return true;
	// }
	// selectedAlien = null;
	// return false;
	// }
	//
	// @Override
	// void run() {
	// if (mouse.isDown(Pointer.KEY_LEFT)) {
	// Coord c = computeMousePos();
	// selectedAlien = parent.findNearestAlien(c);
	// }
	//
	// if (haveAlien()) {
	// Coord sac = selectedAlien.c.copy();
	// sac.sub(parent.getScreenPosition());
	// mgc.drawSight(sac.x, sac.y, 7, colorCycler.process(0xff00ffff));
	//
	// Field[] fs = selectedAlien.getClass().getFields();
	// for (Field f : fs) {
	// AlienProp z = f.getAnnotation(AlienProp.class);
	// if (z!=null) {
	// if (f.getType()==Box.class) {
	//
	// try {
	// Box box = (Box) f.get(selectedAlien);
	// box = box.copy();
	// Coord c = parent.getScreenPosition();
	// c = c.copy();
	// c.mul(-1);
	// box.move(c);
	// mgc.drawTransBox(box.left, box.top, box.width(), box.height(),
	// 0xffff0000, 0x80000000);
	// }
	// catch (IllegalArgumentException e) {
	// throw new RuntimeException(e);
	// }
	// catch (IllegalAccessException e) {
	// throw new RuntimeException(e);
	// }
	// }
	//
	// }
	// }
	// }
	// }
	//
	// @Override
	// String name() {
	// return "alien";
	// }
	// }

	// TODO: reinstate aliens


	public void run() {
		colorCycler.advance();

		if (!tool.ownScreen()) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			parent.drawMap();
			parent.mapperDrawAliens();
		}

		switch (keyboard.justPressed()) {
		case Keyboard.KEY_TAB:
			parent.quitMapper(computeMousePos(true));
			return;
		case Keyboard.KEY_I:
			tool = eyeDropperTool;
			return;
		case Keyboard.KEY_H:
			tool = handTool;
			return;
		case Keyboard.KEY_D:
			tool = drawTool;
			return;
		case Keyboard.KEY_C:
			tool = chooserTool;
			return;
			// case Keyboard.KEY_A:
			// tool.change(alienTool);
			// return;
		}

		drawTool.connect(Keyboard.KEY_SPACE, handTool);
		drawTool.connect(Pointer.KEY_RIGHT, chooserTool);
		eyeDropperTool.connect(Keyboard.KEY_SPACE, handTool);

		Tool t = tool;
		if (otherTool != null) {
			if (otherTool.isFree() && !ukt.isDown(keyThatSustainsTheOtherTool)) {
				otherTool = null;
			}
			else {
				t = otherTool;
			}
		}

		t.run();

		if (!t.ownScreen()) {
			sayIt(t.name());
			if (showTimer != 0) {
				showTimer--;
				bp.showSmallPalette(currentBlock);
			}
			undoRedo();
		}
	}

	private void drawBlockCursor() {
		Coord mousePos = computeMousePos(true);
		Coord box = mousePos.copy();
		box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
		box.sub(parent.getScreenPosition());
		mgc.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, colorCycler.process(COL_CURRENT_BLOCK));
	}

	private void sayIt(String s) {
		if (s!=null) mgc.drawText(10, 10, 0xffffff, s);
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

	@Override
	public void keyboardBlockChoiceAndShow() {
		keyboardBlockChoice();
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

	private Coord computeMousePos(boolean world) {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		if (world) mp.add(parent.getScreenPosition());
		return mp;
	}

	private void blockChoosingMode() {
		keyboardBlockChoice();
		int mx = mouse.getX();
		int my = mouse.getY();

		// System.out.println(String.format("%d,%d", mx, my));
		// drawSight(mx, my, 20, 0xff0000);

		int hoverBlock = bp.showBigPalette(currentBlock, mx, my);
		if (ukt.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			currentBlock = hoverBlock;
		}
	}

	@Override
	public void changeCurrentBlock(int dx, int dy) {
		int delta = bp.getPaletteDelta(dx, dy);
		int b = delta + currentBlock;
		if (b < 0) {
			b += blockCount;
		}
		if (b >= blockCount) {
			b -= blockCount;
		}
		currentBlock = b;
		showBlocks();
	}

	@Override
	public void showBlocks() {
		showTimer = 100;
	}

	@Override
	public EditConsolidator startEdit() {
		System.out.println("Start edit");
		assert edit==null;
		edit = new EditConsolidator(gameMap);
		return edit;
	}

	@Override
	public void endEdit() {
		System.out.println("Submit edit");
		assert edit!=null;
		undoControler.addUndo(edit.endEdit());
		edit=null;
	}

	@Override
	public int getCurrentBlock() {
		return currentBlock;
	}


	@Override
	public void setCurrentBlockFromMap(Coord c) {
		currentBlock = gameMap.getBlock(c);
	}

	@Override
	public void scroll(Coord delta) {
		if (ukt.isDown(Keyboard.KEY_LSHIFT)) {
			delta.mul(2);
		}
		if (ukt.isDown(Keyboard.KEY_LCONTROL)) {
			delta.mul(4);
		}
		parent.moveScreen(delta);
	}

	private void pushTool(int key, Tool tool) {
		keyThatSustainsTheOtherTool = key;
		otherTool = tool;
	}

}
