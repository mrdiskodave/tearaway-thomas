package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.AlienInfo;
import com.nney.tt.AlienInfoMap;
import com.nney.tt.BlockSet;
import com.nney.tt.Const;
import com.nney.tt.WorldServicesToMapper;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.HasKeys;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Locks;
import com.nney.tt.input.LocksKeyAdaptor;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.TeeKeyAdaptor;
import com.nney.tt.map.GameMap;
import com.nney.tt.sprites.AnimsPool;

/**
 * A level editor.
 * 
 * Keys:
 * 
 * <pre>
 * [A] Alien Tool - for changing aliens
 * 		LMB - select alien
 * 		LMB - change alien properties by dragging yellow control points
 * 		LMB - change alien properties by clicking on the panel at the bottom of the screen
 * 		Cursor Keys - nudge a control point by one pixel
 *      [C] - Copy alien to the mouse
 *      [pageup/down] - Choose alien
 *      [N] - New Alien
 * [D] Draw Tool - for changing blocks
 * 		Hold RMB - temporary use of the Block Chooser Tool from the Drawing Tool
 * 		Hold ALT - block choice follows mouse movements
 *                  (useful for drawing multi-block things from the block palette)
 *      Ctrl+CursorKeys change block
 * [B] Block Chooser Tool - full screen current-block choosing tool
 * 		LMB - select block
 * 		Cursor Keys - change block
 * [H] Hand Tool - for panning around
 * 		Hold SHIFT to go faster
 * 
 * Hold:SPACE - temporary use of the Hand Tool from other tools
 * [CTRL+Z] undo (endless - all changes)
 * [CTRL+Y] redo
 * 
 * A mini block chooser that uses CTRL with cursors or '0'.
 * And also CTRL+M to toggle showing block masks.
 * And also CTRL+V to toggle visibility of hidden blocks (magic floors etc).
 * Is available in the Draw
 * </pre>
 * 
 * Mini
 */
public class Mapper implements ButtonPressServices {
	private static final int COPY_LOCK = Locks.LOCK_SHIFT;

	private static final int PASTE_BUFFER_END = Keyboard.KEY_F12;

	private static final int PASTE_BUFFER_START = Keyboard.KEY_F1;

	final static public int MAPPER_KEY = Keyboard.KEY_TAB;

	private static final int COL_BACKGROUND = 0xff0080ff;

	private boolean masksVis;
	private boolean hiddenVis;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	final private int blockCount;
	private int paletteTimer;


	//
	// stuff to do with the message
	//
	// private final String message;
	// private int showMessageTimer;

	final MapperGC mgc;
	final private Pointer mouse;
	final WorldServicesToMapper srv;
	private final GameMap gameMap;

	private final SaveMapBlock[] slots = new SaveMapBlock[12];

	private EditConsolidator edit;

	private CollidableList<BatRecord> bats = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttons = new CollidableList<ButtonRecord>();

	private AlienEdit alienEdit;

	private HoverStatus hoverStatus = new HoverStatus();
	private Alien selectedAlien;

	private MapperMousePosition mmp = new MapperMousePosition();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// -
	// Things that need to be reset on
	// (because playing the game will have
	// messed with the assumptions they hold)

	private UndoControler undoControler;

	private HasKeys keyboard;

	private Runnable pen;

	private Coord marker;

	private boolean alienMode;

	private AlienPalette alienPalette;

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(AlienInfoMap alienInfoMap, AnimsPool animsPool, GameMap gameMap, WorldServicesToMapper srv, Pointer mouse,
			Keyboard keyboard, GraphicsContext gc, Font debugFont) {
		
		this.srv = srv;
		this.gameMap = gameMap;
		this.mouse = mouse;
		this.keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(mouse, keyboard));

		blockCount = srv.getBlocksHolder().getBlockCount();
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(gc, debugFont, colorCycler);
		
		
		ArrayList<AlienInfo> ais = new ArrayList<AlienInfo>();
		for (String name: alienInfoMap.queryNames()) {
			ais.add(alienInfoMap.getByName(name));
		}
		alienPalette = new AlienPalette(ais, mgc, animsPool);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		srv.load(alien);
		setSelectedAlien(alien);
		UndoRedo u = new UndoRedo() {
			@Override
			public void redo() {
				srv.reinstate(alien);
				setSelectedAlien(alien);
			}

			@Override
			public void undo() {
				deleteAlien(alien);
			}
		};
		undoControler.add(u);
	}

	public BlockPalette makeBP() {
		return new BlockPalette(mgc, srv.getBlocksHolder());
	}

	public void init() {
		undoControler = new UndoControler();
	}

	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	void drawBlockCursor() {
		Coord box = mmp.worldBlocks();
		box.mul(Const.BLOCK_SIZE);
		box.sub(srv.getScreenPosition());
		mgc.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mgc.process(COL_CURRENT_BLOCK));
	}

	private static String buttonRecordToString(ButtonRecord br) {
		if (br == null) return "";
		return br.getUniqueName();
	}

	public void run() {
		mgc.nextFrame();

		mmp.update(mouse, getScreenPosition());

		boolean palettes = true;
		int k = keyboard.justPressed();

		if (pen != null) {
			pen.run();
			drawLevel();
		}
		else if (keyboard.isDown(Keyboard.KEY_SPACE)) {
			if (keyboard.isDown(Pointer.KEY_LEFT)) {
				scroll(mmp.pixelsDelta());
			}
			drawLevel();
		}
		else if (keyboard.isDown(Pointer.KEY_RIGHT)) {
			blockSelectionKeys(k);
			blockChoosingMode();
			palettes = false;
		}
		else if (k == MAPPER_KEY) {
			srv.quitMapper(mmp.worldPixels());
			drawLevel();
		}
		else {
			if (alienMode) {
				final BatRecord bat = bats.find(mmp.worldPixels());
				final ButtonRecord button = buttons.find(mmp.screenPixels());

				hoverStatus.move(buttonRecordToString(button));

				if (k == Pointer.KEY_LEFT) {
					if (button != null) {
						hoverStatus.down(buttonRecordToString(button));
						startPen(new Pen2() {
							@Override
							public void up() {
								final ButtonRecord selected = buttons.find(mmp.screenPixels());
								if (hoverStatus.up(buttonRecordToString(selected))) {
									startAlienEdit();
									selected.press();
									endAlienEdit();
								}
							}
						});
					}
					else if (bat == null) {
						startPen(new Pen2() {
							@Override
							void stroke() {
								selectNearestAlien(mmp.worldPixels());
							}
						});
					}
					else {
						final Coord batGrip = mmp.worldPixels().sub2(bat.getPosition());
						startAlienEdit();
						startPen(new Pen2() {
							@Override
							public void stroke() {
								bat.setPosition(mmp.worldPixels().sub2(batGrip));
							}

							@Override
							public void up() {
								endAlienEdit();
							}
						});
					}
				}
				else {
					Coord nudge = getNudge(k);
					if (nudge != null) {
						bat.setPosition(nudge);
					}
				}

				if (haveAlien()) {
					if (k == Keyboard.KEY_DELETE) deleteSelectedAlien();
					if (k == Keyboard.KEY_C) copySelectedAlien();
				}
				if (k == Keyboard.KEY_N) createAlien();
				keyboardAlienChoice(k);
			}
			else {
				if (k == Pointer.KEY_LEFT) {
					startBlockEdit();
					startPen(new Pen2() {
						@Override
						public void stroke() {
							edit.setBlock(mmp.worldBlocks(), getCurrentBlock());
						}

						@Override
						public void up() {
							endBlockEdit();
						}
					});
				}
				if (k == Keyboard.KEY_I) {
					setCurrentBlock(gameMap.getBlock(mmp.worldBlocks()));
				}
				if (k == Keyboard.KEY_M) {
					marker = mmp.worldBlocks();
				}
				if (k == Keyboard.KEY_F) {
					fillRect();
				}
				if (k >= COPY_LOCK + PASTE_BUFFER_START && k <= COPY_LOCK + PASTE_BUFFER_END) {
					int slotNumber = k - (COPY_LOCK + PASTE_BUFFER_START);
					copyRect(slotNumber);
					marker = null;
				}
				if (k >= PASTE_BUFFER_START && k <= PASTE_BUFFER_END) {
					int slotNumber = k - PASTE_BUFFER_START;
					pasteRect(slotNumber);
					marker = null;
				}
				if (keyboard.isDown(Keyboard.KEY_T)) {
					Coord c = mmp.worldBlocksDelta();
					changeCurrentBlock(c.x, c.y);
				}
				blockSelectionKeys(k);
			}

			if (k == Keyboard.KEY_A) {
				alienMode = true;
				paletteTimer = 0;
			}
			if (k == Keyboard.KEY_D) {
				alienMode = false;
				marker = null;
				paletteTimer = 0;
			}

			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Z) undoControler.undo();
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Y) undoControler.redo();
			if (k == Keyboard.KEY_ESCAPE) paletteTimer = 0;

			drawLevel();
			if (!alienMode) {
				drawBlockCursor();
			}
		}

		if (palettes) {
			if (alienMode) showSelectedAlienProps();
			drawPalettes();
		}
	}

	private void startPen(final Pen2 p) {
		p.stroke();
		pen = new Runnable() {
			@Override
			public void run() {
				if (keyboard.isDown(Pointer.KEY_LEFT)) {
					p.stroke();
				}
				else {
					p.up();
					pen = null;
				}
			}
		};
	}

	private void drawPalettes() {
		if (paletteTimer != 0) {
			paletteTimer--;
			if (alienMode) {
				alienPalette.showAlienPalette();
			}
			else {
				makeBP().showSmallPalette(getCurrentBlock());
			}
		}
	}

	private void drawLevel() {
		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
		srv.drawForMapper();

		drawRect();
	}

	private void drawRect() {
		Box box = getRect();
		if (box != null) {
			box.mult(Const.BLOCK_SIZE);
			box.shrink(1);
			box.sub(srv.getScreenPosition());
			mgc.drawBox(box.left, box.top, box.width(), box.height(), mgc.process(0xff00ffff));
		}
	}

	private Box getRect() {
		if (marker == null) return null;
		return Box.fromTwoCorners(mmp.worldBlocks(), marker);
	}

	private void sayIt(String s) {
		if (s != null) {
			mgc.drawText(mgc.screenWidth() - 8 * s.length(), 0, 0xffffff, s);
		}
	}

	private void keyboardAlienChoice(int k) {
		
		AlienInfo current = alienPalette.get();
		if (k == Keyboard.KEY_NEXT) alienPalette.next();
		if (k == Keyboard.KEY_PRIOR) alienPalette.prev();
		if (k == Keyboard.KEY_I && haveAlien()) alienPalette.find(getSelectedAlien().alienInfo);
		if (alienPalette.get()!=current) {
			paletteTimer = 100;
		}
	}

	private void createAlien() {
		AlienInfo ai = alienPalette.get();
		Alien a = srv.instantiateAttachConnect(ai);
		a.resetTo(mmp.worldPixels());
		APS.validateAlien(a);
		createAlienWithUndoRedo(a);
	}

	
	
	void blockSelectionKeys(int k) {
		if (k == Keyboard.KEY_UP) changeCurrentBlock(0, -1);
		if (k == Keyboard.KEY_DOWN) changeCurrentBlock(0, 1);
		if (k == Keyboard.KEY_LEFT) changeCurrentBlock(-1, 0);
		if (k == Keyboard.KEY_RIGHT) changeCurrentBlock(1, 0);
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_M) {
			masksVis = !masksVis;
			srv.setBlockConfig(new BlockSet.Config(masksVis, hiddenVis));
		}
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_V) {
			hiddenVis = !hiddenVis;
			srv.setBlockConfig(new BlockSet.Config(masksVis, hiddenVis));
		}
	}

	void blockChoosingMode() {
		int hoverBlock = makeBP().showBigPalette(getCurrentBlock(), mmp.screenPixels());
		if (keyboard.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			setCurrentBlock(hoverBlock);
		}
	}

	private void changeCurrentBlock(int dx, int dy) {
		int delta = BlockPalette.getPaletteDelta(dx, dy);
		int b = delta + getCurrentBlock();
		if (b < 0) {
			b += blockCount;
		}
		if (b >= blockCount) {
			b -= blockCount;
		}
		setCurrentBlock(b);
	}

	private void startBlockEdit() {
		System.out.println("Start edit");
		assert edit == null;
		edit = new EditConsolidator(gameMap);
	}

	private void endBlockEdit() {
		System.out.println("Submit edit");
		assert edit != null;
		MapSymmetricalUndoRedo u = edit.endEdit();
		if (u != null) submitEdit(u);
		edit = null;
	}

	private void scroll(Coord delta) {
		if (keyboard.isDown(Keyboard.KEY_SHIFT)) {
			delta.mul(4);
		}
		srv.setScreenPosition(srv.getScreenPosition().sub2(delta));
	}

	// --------------------------------------------------

	private void selectNearestAlien(Coord c) {
		setSelectedAlien(srv.findNearestAlien(c));
	}

	private boolean haveAlien() {
		return getSelectedAlien() != null;
	}

	private Alien getSelectedAlien() {
		if (selectedAlien != null && selectedAlien.remove) {
			selectedAlien = null;
		}
		return selectedAlien;
	}

	private void setSelectedAlien(Alien s) {
		this.selectedAlien = s;
	}

	private void showSelectedAlienProps() {
		if (haveAlien()) {
			BatGCImpl batGc = new BatGCImpl(getScreenPosition(), mgc);
			batGc.drawSuperBat(getSelectedAlien().getLocation());

			List<Prop> props = APS.propsForAlien(getSelectedAlien());

			// bats
			bats.clear();
			for (Prop p : props) {
				p.drawAuxBatStuff(batGc);

				ArrayList<Bat> lbats = new ArrayList<Bat>();
				p.getBats(lbats);
				for (Bat lbat : lbats) {
					bats.add(new CommonBatRecord(lbat));
					batGc.drawBat(lbat.where());
				}

			}

			final Alien alien = getSelectedAlien();
			BatRecord superBat = new BatRecord() {
				@Override
				public boolean inside(Coord c) {
					return BatGCImpl.boxForSuperBat(getPosition()).inside(c);
				}

				@Override
				public void setPosition(Coord c) {
					APS.movePropsAbsolute(alien, c);
				}

				@Override
				public Coord getPosition() {
					return alien.getLocation();
				}
			};
			bats.add(superBat);

			// property descriptions and buttons
			buttons.clear();
			StatusLayer statusLayer = new TopDownStatusLayer(mgc);
			PropDrawer pd = new PropDrawer(this, hoverStatus, statusLayer, buttons);
			// pd.draw("Type", selectedAlien.getClass().getSimpleName());
			for (Prop p : props) {
				pd.draw(p);
			}

			// TODO: prop drawer work ...

			// TODO: alien: copy
			// TODO: alien: new (via resetTo())

			// TODO: block editor box select: copy & paste & fill
			// TODO: serialise and deserialise
		}
	}

	private void deleteAlien(Alien a) {
		a.done();
		setSelectedAlien(null);
	}

	public Coord getNudge(int k) {
		switch (k) {
		case Keyboard.KEY_UP:
			return new Coord(0, -1);
		case Keyboard.KEY_DOWN:
			return new Coord(0, 1);
		case Keyboard.KEY_LEFT:
			return new Coord(-1, 0);
		case Keyboard.KEY_RIGHT:
			return new Coord(1, 0);
		}
		return null;
	}

	private void startAlienEdit() {
		assert alienEdit == null;
		Alien a = getSelectedAlien();
		alienEdit = new AlienEdit(a);
	}

	private void endAlienEdit() {
		if (alienEdit.containsAnything()) {
			undoControler.add(alienEdit);
		}
		alienEdit = null;
	}

	@Override
	public Coord screenCentre() {
		return getScreenPosition().add2(mgc.centreDisplacement());
	}

	@Override
	public void setScreenCentre(Coord c) {
		srv.setScreenPosition(c.sub2(mgc.centreDisplacement()));
	}

	public void deleteSelectedAlien() {
		final Alien a = getSelectedAlien();
		undoControler.redoThenAdd(new UndoRedo() {
			@Override
			public void undo() {
				srv.reinstate(a);
				setSelectedAlien(a);
			}

			@Override
			public void redo() {
				deleteAlien(a);
			}
		});
	}

	public void copySelectedAlien() {
		final Alien src = getSelectedAlien();
		if (!src.alienInfo.internal()) {
			final Alien dest = srv.instantiateAttachConnect(src.alienInfo);
			APS.copyProps(src, dest);
			APS.movePropsAbsolute(dest, mmp.worldPixels());
			createAlienWithUndoRedo(dest);
		}
	}

	private void submitEdit(MapSymmetricalUndoRedo u) {
		if (!u.changesNothing()) undoControler.redoThenAdd(u);
	}

	private void pasteRect(int slotNumber) {
		SaveMapBlock slot = slots[slotNumber];
		if (slot != null) {
			Coord c = mmp.worldBlocks();
			// does it fit?
			boolean itFits = c.x + slot.w <= GameMap.MAP_WIDTH && c.y + slot.h <= GameMap.MAP_HEIGHT;
			if (itFits) {
				// paste it!
				MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, c.x, c.y, slot);
				submitEdit(u);
			}
		}
	}

	private void copyRect(int slotNumber) {
		Box rectangle = getRect();
		if (rectangle == null) return;
		SaveMapBlock s = new SaveMapBlock(rectangle.width(), rectangle.height());
		s.read(rectangle.left, rectangle.top, gameMap);
		slots[slotNumber] = s;
		System.out.println("SLOT " + slotNumber);
		// slots[slotNumber].dump();
	}

	private void fillRect() {
		Box rectangle = getRect();
		if (rectangle == null) return;
		SaveMapBlock s = new SaveMapBlock(rectangle.width(), rectangle.height());
		s.fill(getCurrentBlock());
		MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, rectangle.left, rectangle.top, s);
		submitEdit(u);
	}

	private int getCurrentBlock() {
		return currentBlock;
	}

	private void setCurrentBlock(int currentBlock) {
		this.currentBlock = currentBlock;
		paletteTimer = 100;
	}

	//
	// Delegates:
	//

	public Coord getScreenPosition() {
		return srv.getScreenPosition();
	}

	@Override
	public boolean playerFall(Coord where, int fallMax) {
		return srv.playerFall(where, fallMax);
	}
}
