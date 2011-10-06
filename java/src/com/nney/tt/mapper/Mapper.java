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
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.Sprite;

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
public class Mapper implements MapperServicesToPens {
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
	private int showSmallPaletteTimer;

	//
	// stuff to do with the current alien
	//
	private final AlienInfoMap alienInfoMap;
	private TypeCodeTabber<String> alienTabber;
	private int showAlienPaletteTimer;
	private final static int TABBING_ALIENS_OUTSIDE = 1;
	private final static int TABBING_ALIENS_TOTAL = TABBING_ALIENS_OUTSIDE * 2 + 1;
	private final AnimPlayer animPlayers[] = new AnimPlayer[TABBING_ALIENS_TOTAL];
	private static final int ALIENS_TAB_BOX_RADIUS = 70;
	private static final int ALIENS_TAB_BOX_DIAMETER = ALIENS_TAB_BOX_RADIUS * 2 + 1;

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

	// private final Tool alienTool = new GeneralTool(this, Cursor.NONE,
	// "alien", new AlienButtonPressingPen(),
	// new AlienBatMovingPen(), new AlienSelectionPen()) {
	// @Override
	// void run() {
	// super.run();
	// if (isFree()) {
	// int k = srv.justPressed();
	// if (srv.haveAlien()) {
	// if (k == Keyboard.KEY_DELETE) {
	// srv.deleteSelectedAlien();
	// }
	// else if (k == Keyboard.KEY_C) {
	// srv.copySelectedAlien();
	// }
	// }
	// if (k == Keyboard.KEY_N) {
	// srv.createAlien();
	// }
	// srv.keyboardAlienChoice();
	// }
	// }
	//
	// @Override
	// void presentation() {
	// srv.showSelectedAlienProps();
	// };
	// };

	private EditConsolidator edit;

	private CollidableList<BatRecord> bats = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttons = new CollidableList<ButtonRecord>();

	private AlienEdit alienEdit;

	private HoverStatus hs = new HoverStatus();
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

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(AlienInfoMap alienInfoMap, GameMap gameMap, WorldServicesToMapper srv, Pointer mouse,
			Keyboard keyboard, GraphicsContext gc, Font debugFont) {
		this.alienInfoMap = alienInfoMap;
		this.alienTabber = new TypeCodeTabber<String>(alienInfoMap.queryNames());
		this.srv = srv;
		this.gameMap = gameMap;
		this.mouse = mouse;
		this.keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(mouse, keyboard));

		blockCount = srv.getBlocksHolder().getBlockCount();
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(gc, debugFont, colorCycler);

		for (int x = 0; x < TABBING_ALIENS_TOTAL; x++) {
			animPlayers[x] = new AnimPlayer();
		}
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

	class DrawPen implements Pen2 {
		@Override
		public void down() {
			startBlockEdit();
		}

		@Override
		public void stroke() {
			edit.setBlock(mmp.worldBlocks(), getCurrentBlock());
		}

		@Override
		public void up() {
			endBlockEdit();
		}
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
			if (k == Pointer.KEY_MIDDLE) {
				selectNearestAlien(mmp.worldPixels());
			}
			if (k == Pointer.KEY_LEFT) {
				startPen(new DrawPen());
			}
			if (k == Keyboard.KEY_I) {
				setCurrentBlock(gameMap.getBlock(mmp.worldBlocks()));
			}
			if (k == Keyboard.KEY_M) {
				if (marker == null) {
					marker = mmp.worldBlocks();
				}
				else {
					marker = null;
				}
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
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Z) undoControler.undo();
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Y) undoControler.redo();
			if (keyboard.isDown(Keyboard.KEY_T)) {
				Coord c = mmp.worldBlocksDelta();
				changeCurrentBlock(c.x, c.y);
			}
			blockSelectionKeys(k);

			drawLevel();
		}
		if (palettes) {
			drawPalettes();
			showSelectedAlienProps();
		}
	}

	private void startPen(final Pen2 p) {
		if (pen == null) {
			p.down();
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
	}

	private void drawPalettes() {
		if (showSmallPaletteTimer != 0) {
			showSmallPaletteTimer--;
			makeBP().showSmallPalette(getCurrentBlock());
		}
		if (showAlienPaletteTimer != 0) {
			showAlienPaletteTimer--;
			showAlienPalette();
		}
	}

	private void drawLevel() {
		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
		srv.drawForMapper();

		drawRect();
		drawBlockCursor();
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
		Coord corner1 = mmp.worldBlocks();
		Coord corner2 = marker;

		int smallX = Math.min(corner1.x, corner2.x);
		int bigX = Math.max(corner1.x, corner2.x);
		int smallY = Math.min(corner1.y, corner2.y);
		int bigY = Math.max(corner1.y, corner2.y);
		return new Box(smallX, smallY, bigX, bigY);

	}

	private void sayIt(String s) {
		if (s != null) {
			mgc.drawText(mgc.screenWidth() - 8 * s.length(), 0, 0xffffff, s);
		}
	}

	public void keyboardAlienChoice() {
		boolean somethingHappened = true;
		int k = keyboard.justPressed();
		if (k == Keyboard.KEY_NEXT) {
			alienTabber.next();
		}
		else if (k == Keyboard.KEY_PRIOR) {
			alienTabber.prev();
		}
		else if (k == Keyboard.KEY_HOME) {
			alienTabber.home();
		}
		else if (k == Keyboard.KEY_END) {
			alienTabber.end();
		}
		else if (k == Keyboard.KEY_I && haveAlien() && alienTabber.find(getSelectedAlien().alienInfo.name)) {

		}
		else {
			somethingHappened = false;
		}

		if (somethingHappened) {
			showAlienPaletteTimer = 100;
		}
	}

	private void createAlien() {
		AlienInfo ai = getAlienInfo(alienTabber);
		Alien a = srv.instantiateAttachConnect(ai);
		a.resetTo(computeMousePos(CoordType.WORLD_PIXELS));
		APS.validateAlien(a);
		createAlienWithUndoRedo(a);
	}

	private AlienInfo getAlienInfo(TypeCodeTabber<String> tabber) {
		return alienInfoMap.getByName(tabber.get());
	}

	private void showAlienPalette() {
		int sx = mgc.screenWidth() / 2;
		int sy = mgc.screenHeight() / 2;

		TypeCodeTabber<String> at = alienTabber.copy();
		for (int x = 0; x < TABBING_ALIENS_OUTSIDE; x++) {
			at.prev();
			sy -= ALIENS_TAB_BOX_DIAMETER;
		}

		for (int x = 0; x < TABBING_ALIENS_TOTAL; x++) {
			AlienInfo ai = getAlienInfo(at);
			mgc.drawTransBox(sx - ALIENS_TAB_BOX_RADIUS, sy - ALIENS_TAB_BOX_RADIUS, ALIENS_TAB_BOX_DIAMETER,
					ALIENS_TAB_BOX_DIAMETER, mgc.process(0xff00ff00), 0xb00020ff);

			String animsName = ai.animsName();
			if (animsName != null) {
				Anim anim = srv.mapperLoadAnim(animsName);
				animPlayers[x].changeAnimation(anim);
				Sprite sprite = animPlayers[x].nextFrame();
				sprite.drawByHandle(sx, sy, false);
			}

			String s = ai.name;
			s += "(" + ai.typeCode + ")";
			mgc.drawText(sx - ALIENS_TAB_BOX_RADIUS + 5, sy + ALIENS_TAB_BOX_RADIUS - 5 - mgc.charHeight(), 0x80ffff, s);
			sy += ALIENS_TAB_BOX_DIAMETER;
			at.next();
		}
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

	// DIE!
	enum CoordType {
		WORLD_PIXELS, SCREEN_PIXELS, WORLD_BLOCKS, DELTA_PIXELS, DELTA_BLOCKS
	}

	// DIE!
	Coord computeMousePos(CoordType ct) {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		if (ct == CoordType.SCREEN_PIXELS) return mp;
		mp.add(getScreenPosition());
		if (ct == CoordType.WORLD_PIXELS) return mp;
		mp.div(Const.BLOCK_SIZE);
		return mp;
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

	@Override
	public void selectNearestAlien(Coord c) {
		System.out.println("nearest...");
		setSelectedAlien(srv.findNearestAlien(c));
	}

	public boolean haveAlien() {
		return getSelectedAlien() != null;
	}

	public Alien getSelectedAlien() {
		if (selectedAlien != null && selectedAlien.remove) {
			selectedAlien = null;
		}
		return selectedAlien;
	}

	public void setSelectedAlien(Alien s) {
		this.selectedAlien = s;
	}

	@Override
	public void showSelectedAlienProps() {
		if (haveAlien()) {
			Coord sac = getSelectedAlien().getLocation().copy();
			sac.sub(getScreenPosition());
			mgc.drawSight2(sac.x, sac.y, 25, mgc.process(0xff00ffff), BatGCImpl.SUPERBAT_SIZE, 0x40000000);

			List<Prop> props = APS.propsForAlien(getSelectedAlien());

			// bats
			bats.clear();
			for (Prop p : props) {
				BatGCImpl batGc = new BatGCImpl(getScreenPosition(), mgc);
				p.drawAuxBatStuff(batGc);

				ArrayList<Bat> lbats = new ArrayList<Bat>();
				p.getBats(lbats);
				for (Bat lbat : lbats) {
					bats.add(new CommonBatRecord(lbat));
					batGc.drawBat(lbat.where());
				}

			}
			bats.add(new SuperBatRecord(getSelectedAlien()));

			// property descriptions and buttons
			buttons.clear();
			StatusLayer statusLayer = new BottomUpStatusLayer(mgc);
			PropDrawer pd = new PropDrawer(this, hs, statusLayer, buttons);
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
		if (a == getSelectedAlien()) {
			setSelectedAlien(null);
		}
	}

	@Override
	public BatRecord findBat(Coord c) {
		return bats.find(c);
	}

	@Override
	public ButtonRecord findButton(Coord c) {
		return buttons.find(c);
	}

	@Override
	public Coord getNudge() {
		switch (keyboard.justPressed()) {
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

	@Override
	public void startAlienEdit() {
		Alien a = getSelectedAlien();
		alienEdit = new AlienEdit(a);
	}

	@Override
	public void endAlienEdit() {
		int size = alienEdit.size();
		if (size != 0) {
			undoControler.add(alienEdit);
		}
	}

	@Override
	public HoverStatus getHoverStatus() {
		return hs;
	}

	@Override
	public Coord screenCentre() {
		Coord centerDisplacement = new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
		return getScreenPosition().add2(centerDisplacement);
	}

	@Override
	public void setScreenCentre(Coord c) {
		Coord centerDisplacement = new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
		srv.setScreenPosition(c.sub2(centerDisplacement));
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

			Coord diff = computeMousePos(CoordType.WORLD_PIXELS).sub2(src.getLocation());
			APS.moveProps(dest, diff);
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
		showSmallPaletteTimer = 100;
	}

	//
	// Delegates:
	//

	public Coord getScreenPosition() {
		return srv.getScreenPosition();
	}

	int justPressed() {
		return keyboard.justPressed();
	}

	boolean isDown(int key) {
		return keyboard.isDown(key);
	}

	MapperGC getMGC() {
		return mgc;
	}

	@Override
	public boolean playerFall(Coord where, int fallMax) {
		return srv.playerFall(where, fallMax);
	}
}
