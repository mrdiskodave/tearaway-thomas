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
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.UnifiedKeyTester;
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
 * [D] Draw Tool - for changing blocks
 * 		Hold RMB - temporary use of the Block Chooser Tool from the Drawing Tool
 * 		Hold CTRL - block choice follows mouse movements
 *                  (useful for drawing multi-block things from the block palette)
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
//	private final String message;
//	private int showMessageTimer;

	final MapperGC mgc;
	final private Pointer mouse;
	final WorldServicesToMapper srv;
	private final GameMap gameMap;

	private final UnifiedKeyTester ukt2;
	private final SaveMapBlock[] slots = new SaveMapBlock[12];

	private final Tool blockChooserTool = new BlockChooserTool(this);
	private final Tool rectangleTool = new RectangleTool(this);
	private final Tool drawTool = new GeneralTool(this, Cursor.BLOCK, "draw", new BlockTrackingPen(), new EyeDropperPen(), new DrawingPen()) {
		@Override
		void run() {
			super.run();
			srv.keyboardBlockChoice(false);
			srv.perhapsPaste();
		};
	};
	private final Tool handTool = new GeneralTool(this, Cursor.NONE, "hand", new HandPen());
	private final Tool alienTool = new GeneralTool(this, Cursor.NONE, "alien", new AlienButtonPressingPen(),
			new AlienBatMovingPen(), new AlienSelectionPen()) {
		@Override
		void run() {
			super.run();
			if (isFree()) {
				int k = srv.justPressed();
				if (srv.haveAlien()) {
					if (k==Keyboard.KEY_DELETE) {
						srv.deleteSelectedAlien();
					}
					else if (k==Keyboard.KEY_C) {
						srv.copySelectedAlien();
					}
				}
				if (k==Keyboard.KEY_N){
					srv.createAlien();
				}
				srv.keyboardAlienChoice();
			}
		}
		
		@Override
		void presentation() {
			srv.showSelectedAlienProps();
		};
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

	private UnifiedKeyTester keyboard;

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
		this.ukt2 = new UnifiedKeyTester(mouse, keyboard);
		this.keyboard = ukt2;
		blockCount = srv.getBlocksHolder().getBlockCount();
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(gc, debugFont, colorCycler);
		tool = drawTool;

		drawTool.addNested(Keyboard.KEY_SPACE, handTool);
		drawTool.addNested(Pointer.KEY_RIGHT, blockChooserTool);
		alienTool.addNested(Keyboard.KEY_SPACE, handTool);
		rectangleTool.addNested(Keyboard.KEY_SPACE, handTool);
		rectangleTool.addNested(Pointer.KEY_RIGHT, blockChooserTool);

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

	public void run() {
		mgc.nextFrame();
		ukt2.nextFrame();
		
//		int k = justPressed();
//		if (k!=0) {
//			System.out.println("JustPressed:"+k);
//		}

//		System.out.println("---");
		if (!tool.ownScreen()) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			srv.drawForMapper();
		}

		Tool t = tool;
		if (otherTool != null) {
			if (otherTool.isFree() && !keyboard.isDown(keyThatSustainsTheOtherTool)) {
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
				makeBP().showSmallPalette(getCurrentBlock());
			}
			if (showAlienPaletteTimer != 0) {
				showAlienPaletteTimer--;
				showAlienPalette();
			}
		}

		if (t.isFree()) {
			undoRedo();
			switch (keyboard.justPressed()) {
			case MAPPER_KEY:
				srv.quitMapper(computeMousePos(CoordType.WORLD_PIXELS));
				return;
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
				tool = rectangleTool;
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

	private void sayIt(String s) {
		if (s != null) {
			mgc.drawText(mgc.screenWidth() - 8 * s.length(), 0, 0xffffff, s);
		}
	}

	private void undoRedo() {
		if (keyboard.isDown(Keyboard.KEY_CONTROL)) {
			switch (keyboard.justPressed()) {
			case Keyboard.KEY_Z:
				undoControler.undo();
				break;
			case Keyboard.KEY_Y:
				undoControler.redo();
				break;
			}
		}
	}

	public void keyboardAlienChoice() {
		boolean somethingHappened = true;
		int k = keyboard.justPressed();
		if (k==Keyboard.KEY_NEXT) {
			alienTabber.next();
		}
		else if (k==Keyboard.KEY_PRIOR) {
			alienTabber.prev();
		}
		else if (k==Keyboard.KEY_HOME) {
			alienTabber.home();
		}
		else if (k==Keyboard.KEY_END) {
			alienTabber.end();
		}
		else if (k==Keyboard.KEY_I && haveAlien() && alienTabber.find(getSelectedAlien().alienInfo.name)) {
			
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
			if (animsName!=null) {
				Anim anim = srv.mapperLoadAnim(animsName);
				animPlayers[x].changeAnimation(anim);
				Sprite sprite = animPlayers[x].nextFrame();
				sprite.drawByHandle(sx, sy, false);
			}

			String s = ai.name;
			s += "("+ai.typeCode+")";
			mgc.drawText(sx - ALIENS_TAB_BOX_RADIUS + 5, sy + ALIENS_TAB_BOX_RADIUS - 5 - mgc.charHeight(), 0x80ffff, s);
			sy += ALIENS_TAB_BOX_DIAMETER;
			at.next();
		}
	}

	@Override
	public void keyboardBlockChoice(boolean fullScreen) {
		if (!fullScreen && !keyboard.isDown(Keyboard.KEY_CONTROL)) {
			return;
		}

		int jp = keyboard.justPressed();
		if (jp == 0) return;
		switch (jp) {
		case Keyboard.KEY_0:
			setCurrentBlock(0);
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
			masksVis = !masksVis;
			srv.setBlockConfig(new BlockSet.Config(masksVis, hiddenVis));
			break;
		case Keyboard.KEY_V:
			hiddenVis = !hiddenVis;
			srv.setBlockConfig(new BlockSet.Config(masksVis, hiddenVis));
			break;
		}
	}

	enum CoordType {
		WORLD_PIXELS, SCREEN_PIXELS, WORLD_BLOCKS
	}

	Coord computeMousePos(CoordType ct) {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		if (ct == CoordType.SCREEN_PIXELS) return mp;
		mp.add(getScreenPosition());
		if (ct == CoordType.WORLD_PIXELS) return mp;
		mp.div(Const.BLOCK_SIZE);
		return mp;
	}

	void blockChoosingMode() {
		keyboardBlockChoice(true);
		int hoverBlock = makeBP().showBigPalette(getCurrentBlock(), computeMousePos(CoordType.SCREEN_PIXELS));
		if (keyboard.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			setCurrentBlock(hoverBlock);
		}
	}

	@Override
	public void changeCurrentBlock(int dx, int dy) {
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
		MapSymmetricalUndoRedo u = edit.endEdit();
		if (u != null) submitEdit(u);
		edit = null;
	}

	@Override
	public int getCurrentBlock() {
		return currentBlock;
	}

	@Override
	public void setCurrentBlockFromMap(Coord c) {
		setCurrentBlock(gameMap.getBlock(c));
	}

	@Override
	public void scroll(Coord delta) {
		if (keyboard.isDown(Keyboard.KEY_SHIFT)) {
			delta.mul(4);
		}
		srv.setScreenPosition(srv.getScreenPosition().add2(delta));
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
				for (Bat lbat: lbats) {
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

	public void copyRect(int slotNumber, Box rectangle) {
		SaveMapBlock s = new SaveMapBlock(rectangle.width(), rectangle.height());
		s.read(rectangle.left, rectangle.top, gameMap);
		slots[slotNumber] = s;
		System.out.println("SLOT " + slotNumber);
		// slots[slotNumber].dump();
	}

	@Override
	public void perhapsPaste() {
		int k = keyboard.justPressed();
		if (k >= Keyboard.KEY_F1 && k <= Keyboard.KEY_F12) {
			int slotNumber = k - Keyboard.KEY_F1;
			SaveMapBlock slot = slots[slotNumber];
			if (slot != null) {
				Coord c = computeMousePos(CoordType.WORLD_BLOCKS);
				// does it fit?
				boolean itFits = c.x + slot.w <= GameMap.MAP_WIDTH && c.y + slot.h <= GameMap.MAP_HEIGHT;
				if (itFits) {
					// paste it!
					MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, c.x, c.y, slot);
					submitEdit(u);
				}
			}
		}
	}

	private void submitEdit(MapSymmetricalUndoRedo u) {
		if (!u.changesNothing()) undoControler.redoThenAdd(u);
	}

	public void fillRect(Box rectangle) {
		SaveMapBlock s = new SaveMapBlock(rectangle.width(), rectangle.height());
		s.fill(getCurrentBlock());
		MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, rectangle.left, rectangle.top, s);
		submitEdit(u);
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
