package com.nney.tt.mapper;

import java.util.List;

import com.nney.tt.AlienInfoMap;
import com.nney.tt.WorldServicesToMapper;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.UnifiedKeyTester;
import com.nney.tt.map.GameMap;

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
 * [D] Draw Tool - for changing blocks
 * 		Hold:RMB - temporary use of the Block Chooser Tool from the Drawing Tool
 * 		Cursor Keys - mini block chooser
 * 		Hold:CTRL - block choice follows mouse movements
 *                  (useful for drawing multi-block things from the block palette)
 * [B] Block Chooser Tool - full screen current-block choosing tool
 * 		LMB - select block
 * 		Cursor Keys - change block
 * [I] Eyedropper Tool - for picking the current-block from the map
 * 		Cursor Keys - mini block chooser
 * [H] Hand Tool - for panning around
 * 		CTRL, SHIFT or CTRL+SHIFT give various levels of acceleration
 * 
 * Hold:SPACE - temporary use of the Hand Tool from other tools
 * [Z] undo (endless - all changes)
 * [Y] redo
 * </pre>
 */
public class Mapper implements PenServices {

	private static final int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	final private int blockCount;
	private int showSmallPaletteTimer;

	final MapperGC mgc;
	final private Pointer mouse;
	final private Keyboard keyboard;
	final WorldServicesToMapper srv;
	private final GameMap gameMap;

	final UnifiedKeyTester ukt;

	private Tool blockChooserTool = new ChooserTool(this);
	private Tool bigBoxTool = new BigBoxTool(this);
	private Tool drawTool = new GeneralTool(this, Cursor.BLOCK, "draw", new BlockTrackingPen(), new DrawingPen());
	private Tool eyeDropperTool = new GeneralTool(this, Cursor.BLOCK, "eyeDropper", new EyeDropperPen());
	private Tool handTool = new GeneralTool(this, Cursor.NONE, "hand", new HandPen());
	private Tool alienTool = new GeneralTool(this, Cursor.NONE, "alien", new AlienButtonPressingPen(),
			new AlienBatMovingPen(), new AlienSelectionPen()) {
		@Override
		void run() {
			super.run();
			if (haveAlien() && isFree()) {
				switch (keyboard.justPressed()) {
				case Keyboard.KEY_DELETE:
					deleteSelectedAlien();
					break;
				case Keyboard.KEY_C:
					copySelectedAlien();
					break;
				}
			}
		}
	};

	private Tool tool;
	private Tool otherTool;

	private int keyThatSustainsTheOtherTool;

	private EditConsolidator edit;

	private CollidableList<BatRecord> bats = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttons = new CollidableList<ButtonRecord>();

	private AlienEdit alienEdit;

	private HoverStatus hs = new HoverStatus();
	private Alien selectedAlien;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// -
	// Things that need to be reset on
	// (because playing the game will have
	// messed with the assumptions they hold)

	private UndoControler undoControler;

	private final AlienInfoMap alienInfoMap;


	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(AlienInfoMap alienInfoMap, GameMap gameMap, WorldServicesToMapper srv, Pointer mouse, Keyboard keyboard,
			GraphicsContext gc, Font debugFont) {
		this.alienInfoMap = alienInfoMap;
		this.srv = srv;
		this.gameMap = gameMap;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.ukt = new UnifiedKeyTester(mouse, keyboard);
		blockCount = srv.getBlocksHolder().getBlockCount();
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(gc, debugFont, colorCycler);
		tool = drawTool;

		drawTool.addNested(Keyboard.KEY_SPACE, handTool);
		drawTool.addNested(Pointer.KEY_RIGHT, blockChooserTool);
		eyeDropperTool.addNested(Keyboard.KEY_SPACE, handTool);
		alienTool.addNested(Keyboard.KEY_SPACE, handTool);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		srv.loadAlienIntoWorld(alien);
		setSelectedAlien(alien);
		UndoRedo u = new UndoRedo() {
			@Override
			public void redo() {
				srv.reinstateAlien(alien);
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

	public void run() {
		mgc.nextFrame();
		ukt.next();

		if (!tool.ownScreen()) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			srv.drawMap();
			srv.drawAliensForMapper();

			drawMapBounds();
		}

		Tool t = tool;
		if (otherTool != null) {
			if (otherTool.isFree() && !ukt.isDown(keyThatSustainsTheOtherTool)) {
				otherTool = null;
				System.out.println("POP TOOL");
			}
			else {
				t = otherTool;
			}
		}

		t.presentation();
		if (t == otherTool) {
			tool.presentation();
		}
		t.run();

		if (!t.ownScreen()) {
			sayIt(t.name());
			if (showSmallPaletteTimer != 0) {
				showSmallPaletteTimer--;
				makeBP().showSmallPalette(currentBlock);
			}
		}

		if (t.isFree()) {
			undoRedo();
			switch (keyboard.justPressed()) {
			case Keyboard.KEY_TAB:
				srv.quitMapper(computeMousePos(true));
				return;
			case Keyboard.KEY_I:
				tool = eyeDropperTool;
				break;
			case Keyboard.KEY_H:
				tool = handTool;
				break;
			case Keyboard.KEY_D:
				tool = drawTool;
				break;
			case Keyboard.KEY_B:
				tool = blockChooserTool;
				break;
			case Keyboard.KEY_R:
				tool = bigBoxTool;
				break;
			case Keyboard.KEY_A:
				tool = alienTool;
				break;
			}
		}

		if (haveAlien()) {
			getSelectedAlien().onPropUpdate();
		}
	}

	/**
	 * Big box.
	 * Big box tool.
	 * Four keys to set the edge of the big-box.
	 * Current block selection shortcuts all work (arrows and RMB).
	 * [F] fill bigbox.
	 * Function keys take a copy of the big-box (function keys in draw mode paste that stuff).
	 * 
	 * [G] get map bounds
	 * [S] set map bounds
	 * 
	 * big box should probably look different (different color?) if it is the map bounds
	 * 
	 * 
	 */
	private void drawMapBounds() {
	}


	private void sayIt(String s) {
		if (s != null) {
			mgc.drawText(mgc.screenWidth() - 8 * s.length(), 0, 0xffffff, s);
		}
	}

	private void undoRedo() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_Z:
			undoControler.undo();
			break;
		case Keyboard.KEY_Y:
			undoControler.redo();
			break;
		}
	}

	@Override
	public void keyboardBlockChoice() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_0:
			currentBlock = 0;
			break;
		case Keyboard.KEY_UP:
			changeCurrentBlock(0, -1);
			break;
		case Keyboard.KEY_DOWN:
			changeCurrentBlock(0, 1);
			break;
		case Keyboard.KEY_LEFT:
			changeCurrentBlock(-1, 0);
			break;
		case Keyboard.KEY_RIGHT:
			changeCurrentBlock(1, 0);
			break;
		case Keyboard.KEY_M:
			srv.toggleSeeMasks();
			break;
		case Keyboard.KEY_V:
			srv.toggleShowInvisible();
			break;
		}
	}

	Coord computeMousePos(boolean world) {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		if (world) mp.add(srv.getScreenPosition());
		return mp;
	}

	void blockChoosingMode() {
		keyboardBlockChoice();
		int hoverBlock = makeBP().showBigPalette(currentBlock, computeMousePos(false));
		if (ukt.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			currentBlock = hoverBlock;
		}
	}

	@Override
	public void changeCurrentBlock(int dx, int dy) {
		int delta = BlockPalette.getPaletteDelta(dx, dy);
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
		showSmallPaletteTimer = 100;
	}

	@Override
	public EditDestination startBlockEdit() {
		System.out.println("Start edit");
		assert edit == null;
		edit = new EditConsolidator(gameMap);
		return edit;
	}

	@Override
	public void endBlockEdit() {
		System.out.println("Submit edit");
		assert edit != null;
		UndoRedo u = edit.endEdit();
		if (u != null) undoControler.redoThenAdd(u);
		edit = null;
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
		srv.moveScreen(delta);
	}

	void pushTool(int key, Tool tool) {
		System.out.println("PUSH TOOL");
		keyThatSustainsTheOtherTool = key;
		otherTool = tool;
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
			Coord sac = getSelectedAlien().c.copy();
			sac.sub(srv.getScreenPosition());
			mgc.drawSight2(sac.x, sac.y, 25, mgc.process(0xff00ffff), BatGCImpl.SUPERBAT_GIRTH, 0x40000000);

			List<Prop> props = APS.propsForAlien(getSelectedAlien());

			// bats
			bats.clear();
			for (Prop p : props) {
				BatGCImpl batGc = new BatGCImpl(srv.getScreenPosition(), mgc);
				p.drawAuxBatStuff(batGc);

				Coord[] bps = p.getBats();
				if (bps != null) {
					for (int x = 0; x < bps.length; x++) {
						bats.add(new CommonBatRecord(p, x, bps[x]));
					}

					for (Coord c : bps) {
						batGc.drawBat(c);
					}
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

	String padTo(String s, int x) {
		int l = s.length();
		StringBuffer b = new StringBuffer(s.substring(0, Math.min(x, l)));
		while (l < x) {
			b.append(' ');
			l++;
		}
		return b.toString();
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
		alienEdit = new AlienEdit(APS.propsForAlien(getSelectedAlien()));
	}

	@Override
	public void endAlienEdit() {
		int size = alienEdit.size();
		System.out.println(size + " fields changed!");
		if (size != 0) {
			undoControler.add(alienEdit);
		}
		getSelectedAlien().onPropUpdate();
	}

	@Override
	public HoverStatus getHoverStatus() {
		return hs;
	}

	@Override
	public Coord screenCentre() {
		Coord centerDisplacement = new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
		Coord c = srv.getScreenPosition();
		c = c.copy();
		c.add(centerDisplacement);
		return c;
	}

	@Override
	public void setScreenCentre(Coord c) {
		Coord centerDisplacement = new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
		c = c.copy();
		c.sub(centerDisplacement);
		srv.setScreenPosition(c);
	}

	public void deleteSelectedAlien() {
		final Alien a = getSelectedAlien();
		undoControler.redoThenAdd(new UndoRedo() {
			@Override
			public void undo() {
				srv.reinstateAlien(a);
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
		if (src.typeCode >= 0) {
			final Alien dest = srv.createAlien(src.typeCode);
			APS.copyProps(src, dest);

			Coord diff = computeMousePos(true).sub2(src.c);
			APS.moveProps(dest, diff);
			createAlienWithUndoRedo(dest);
		}
	}

	
	
	
	
	
	
	public Coord getScreenPosition() {
		return srv.getScreenPosition();
	}
	
	int justPressed() {
		return ukt.justPressed();
	}

	boolean isDown(int key) {
		return ukt.isDown(key);
	}


	MapperGC getMGC() {
		return mgc;
	}

}
