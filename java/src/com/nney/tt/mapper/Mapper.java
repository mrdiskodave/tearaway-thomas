package com.nney.tt.mapper;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import com.nney.tt.Const;
import com.nney.tt.MapperServices;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;
import com.nney.tt.aliens.AlienWithGeneratedLocation;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
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
 * A Alien Tool - for changing aliens
 * 		LMB - select alien
 * 		LMB - change alien properties by dragging yellow control points
 * 		LMB - change alien properties by clicking on the panel at the bottom of the screen
 * 		Cursor Keys - nudge a control point by one pixel
 *      C - Copy alien to the mouse (other graphical control points stay unchanged)
 * D Draw Tool - for changing blocks
 * 		Hold:RMB - temporary use of the Block Chooser Tool from the Drawing Tool
 * 		Cursor Keys - mini block chooser
 * 		Hold:Left CTRL - block choice follows mouse movements
 *                       (useful for drawing multi-block things from the block palette)
 * B Block Chooser Tool - full screen current-block choosing tool
 * 		LMB - select block
 * 		Cursor Keys - change block
 * I Eyedropper Tool - for picking the current-block from the map
 * 		Cursor Keys - mini block chooser
 * H Hand Tool - for panning around
 * 		CTRL, SHIFT or CTRL+SHIFT give various levels of acceleration
 * 
 * Hold:SPACE - temporary use of the Hand Tool from other tools
 * Z undo (endless - all changes)
 * Y redo
 * </pre>
 */
public class Mapper implements PenServices {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	private static final int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	final private int blockCount;
	private int showSmallPaletteTimer;
	private BlockPalette bp;

	final private MapperGC mgc;
	final private Pointer mouse;
	final private Keyboard keyboard;
	private final MapperServices parent;
	private final GameMap gameMap;

	private UndoControler undoControler = new UndoControler();
	private ColorCycler colorCycler = new ColorCycler();
	final private UnifiedKeyTester ukt;

	private Tool blockChooserTool = new ChooserTool();
	private Tool drawTool = new GeneralTool(this, Cursor.BLOCK, "draw", new BlockTrackingPen(), new DrawingPen());
	private Tool eyeDropperTool = new GeneralTool(this, Cursor.BLOCK, "eyeDropper", new EyeDropperPen());
	private Tool handTool = new GeneralTool(this, Cursor.NONE, "hand", new HandPen());
	private Tool alienTool = new GeneralTool(this, Cursor.NONE, "alien", new AlienButtonPressingPen(),
			new AlienBatMovingPen(), new AlienSelectionPen()) {
		@Override
		void run() {
			super.run();
			if (haveAlien()) {
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

	private Alien selectedAlien;

	
	private CollidableList<BatRecord> bats = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttons = new CollidableList<ButtonRecord>();

	private AlienEdit alienEdit;

	private HoverStatus hs = new HoverStatus();

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, MapperServices srv, Pointer mouse, Keyboard keyboard, GraphicsContext gc,
			Font debugFont) {
		this.parent = srv;
		this.gameMap = gameMap;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.ukt = new UnifiedKeyTester(mouse, keyboard);
		blockCount = srv.getBlocksHolder().getBlockCount();
		mgc = new MapperGC(gc, debugFont);
		createBlockPalette();
		tool = drawTool;

		drawTool.addNested(Keyboard.KEY_SPACE, handTool);
		drawTool.addNested(Pointer.KEY_RIGHT, blockChooserTool);
		eyeDropperTool.addNested(Keyboard.KEY_SPACE, handTool);
		alienTool.addNested(Keyboard.KEY_SPACE, handTool);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		parent.loadAlienIntoWorld(alien);
		setSelectedAlien(alien);
		UndoRedo u = new UndoRedo() {
			@Override
			public void redo() {
				parent.reinstateAlien(alien);
				setSelectedAlien(alien);
			}

			@Override
			public void undo() {
				deleteAlien(alien);
			}
		};
		undoControler.add(u);
	}

	private void createBlockPalette() {
		bp = new BlockPalette(colorCycler, mgc, parent.getBlocksHolder());
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

	private class GeneralTool extends Tool {
		private final Pen[] pens;
		private final String name;
		private final Cursor cursor;

		GeneralTool(PenServices srv, Cursor cursor, String name, Pen... pens) {
			for (Pen pen : pens) {
				pen.srv = srv;
			}
			this.cursor = cursor;
			this.name = name;
			this.pens = pens;
		}

		@Override
		void presentation() {
			for (Pen pen : pens) {
				pen.presentation();
			}
			for (Pen pen : pens) {
				if (cursor == Cursor.BLOCK) {
					drawBlockCursor();
				}
			}
		}

		@Override
		void run() {
			if (isFree()) {
				for (Entry<Integer, Tool> e : nest.entrySet()) {
					if (ukt.justPressed() == e.getKey()) {
						pushTool(e.getKey(), e.getValue());
					}
				}
			}

			for (Pen pen : pens) {
				Coord m = computeMousePos(pen.usesWorldCoords());
				if (pen.active) {
					boolean held = ukt.isDown(pen.key());
					if (held) {
						pen.stroke(m.copy());
					}
					else {
						pen.up(m.copy());
						pen.active = false;
						lessBusy();
					}
				}
				else {
					boolean pressed = ukt.justPressed() == pen.key();
					if (pressed) {
						boolean more = pen.down(m.copy());
						pen.active = true;
						moreBusy();
						if (!more) break;
					}
					else {
						pen.hover(m.copy());
					}
				}
			}
		}

		@Override
		String name() {
			return name;
		}
	}

	public void run() {
		colorCycler.advance();
		ukt.next();

		if (!tool.ownScreen()) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			parent.drawMap();
			parent.drawAliensForMapper();
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
				bp.showSmallPalette(currentBlock);
			}
		}

		if (t.isFree()) {
			undoRedo();
			switch (keyboard.justPressed()) {
			case Keyboard.KEY_TAB:
				parent.quitMapper(computeMousePos(true));
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
			case Keyboard.KEY_A:
				tool = alienTool;
				break;
			}
		}

		if (selectedAlien!=null) {
			selectedAlien.onPropUpdate();
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
			parent.toggleSeeMasks();
			createBlockPalette();
			break;
		case Keyboard.KEY_V:
			parent.toggleShowInvisible();
			createBlockPalette();
			break;
		}
	}

	private Coord computeMousePos(boolean world) {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		if (world) mp.add(parent.getScreenPosition());
		return mp;
	}

	private void blockChoosingMode() {
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
			parent.toggleSeeMasks();
			createBlockPalette();
			break;
		case Keyboard.KEY_V:
			parent.toggleShowInvisible();
			createBlockPalette();
			break;
		}
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
		parent.moveScreen(delta);
	}

	private void pushTool(int key, Tool tool) {
		System.out.println("PUSH TOOL");
		keyThatSustainsTheOtherTool = key;
		otherTool = tool;
	}

	// --------------------------------------------------

	public boolean haveAlien() {
		if (getSelectedAlien() != null && !getSelectedAlien().remove) {
			return true;
		}
		// just to help garbage collection
		setSelectedAlien(null);
		return false;
	}

	@Override
	public void selectNearestAlien(Coord c) {
		System.out.println("nearest...");
		setSelectedAlien(parent.findNearestAlien(c));
	}

	public Alien getSelectedAlien() {
		return selectedAlien;
	}

	public void setSelectedAlien(Alien s) {
		this.selectedAlien = s;
	}

	List<Prop> propsForAlien(Alien alien) {
		assert alien != null;
		List<Prop> props = new ArrayList<Prop>();
		Field[] fields = alien.getClass().getFields();
		for (Field field : fields) {
			AlienProp p = field.getAnnotation(AlienProp.class);
			if (p != null && !(p.xtraDef().equals("location") && alien instanceof AlienWithGeneratedLocation)) {
				Prop prop = null;
				PropPack pp = new PropPack(alien, field);
				Class<?> ft = field.getType();

				if (ft == Box.class) {
					prop = new BoxVisualProp(pp);
				}
				else if (ft == XRange.class) {
					prop = new XRangeVisualProp(pp);
				}
				else if (ft == Coord.class) {
					prop = new CoordVisualProp(pp);
				}
				else if (ft == boolean.class) {
					prop = new BooleanProp(pp);
				}
				else {
					System.out.println(ft);
					assert false;
				}
				assert prop != null;
				props.add(0, prop);
			}
		}
		return props;
	}

	@Override
	public void showSelectedAlienProps() {
		if (haveAlien()) {
			Coord sac = getSelectedAlien().c.copy();
			sac.sub(parent.getScreenPosition());
			mgc.drawSight(sac.x, sac.y, 16, colorCycler.process(0xff00ffff));

			List<Prop> props = propsForAlien(selectedAlien);

			// bats
			bats.clear();
			for (Prop p : props) {
				BatGCImpl batGc = new BatGCImpl(parent.getScreenPosition(), mgc);
				p.drawAuxBatStuff(batGc);
				
				Coord[] bps = p.getBats();
				if (bps!=null) {
					for (int x=0; x<bps.length; x++) {
						bats.add(new BatRecord(p, x, bps[x]));
					}
					
					for (Coord c: bps) {
						batGc.drawBat(c);
					}
				}
			}
			
			// TODO: what if the bats and buttons moved inside the Prop?
			// bats and the drawing of them are also intermished
			// what do I really want out of this??
			//
			// Objective:
			// I want to move all the visualprops along as part of alien-copy
			// (not just move the aliens location but all its other stuff as well)
			// otherwise you can't easilly tell that you've copied it!
			//
			

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
		alienEdit = new AlienEdit(propsForAlien(selectedAlien));
	}

	@Override
	public void endAlienEdit() {
		int size = alienEdit.size();
		System.out.println(size + " fields changed!");
		if (size != 0) {
			undoControler.add(alienEdit);
		}
		selectedAlien.onPropUpdate();
	}

	@Override
	public HoverStatus getHoverStatus() {
		return hs;
	}

	@Override
	public Coord screenCentre() {
		Coord centerDisplacement = new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
		Coord c = parent.getScreenPosition();
		c = c.copy();
		c.add(centerDisplacement);
		return c;
	}

	@Override
	public void setScreenCentre(Coord c) {
		Coord centerDisplacement = new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
		c = c.copy();
		c.sub(centerDisplacement);
		parent.setScreenPosition(c);
	}

	public void deleteSelectedAlien() {
		final Alien a = getSelectedAlien();
		undoControler.redoThenAdd(new UndoRedo() {
			@Override
			public void undo() {
				parent.reinstateAlien(a);
				setSelectedAlien(a);
			}

			@Override
			public void redo() {
				deleteAlien(a);
			}
		});
	}

	public void copySelectedAlien() {
		final Alien a = selectedAlien;
		if (a.typeCode >= 0) {
			final Alien z = parent.createAlien(a.typeCode);
			
			{
				List<Prop> zps = propsForAlien(z);
				List<Prop> aps = propsForAlien(a);
				assert aps.size() == zps.size();
				for (int x = 0; x < aps.size(); x++) {
					zps.get(x).copyFrom(aps.get(x));
				}
			}

			{
				// need to rebind to the props as
				// we have set their values
				// i.e. the objects will now be somewhere else
				List<Prop> zps = propsForAlien(z);
				Coord mp = computeMousePos(true);
				Coord diff = mp.copy();
				diff.sub(a.c);
				System.out.println("DIFF!"+diff);
				for (Prop zp: zps) {
					zp.moveBy(diff);
				}
				
				// though the alien's location will
				// probably have changed it might have a computed location
				// so change it here to be sure
				z.c = mp;
				z.onPropUpdate();
			}
			
			createAlienWithUndoRedo(z);
		}
	}

}
