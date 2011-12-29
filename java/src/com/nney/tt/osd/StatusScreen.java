package com.nney.tt.osd;

import java.util.Stack;

import com.nney.tt.gfx.Colours;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.MultiDisposable;
import com.nney.utils.Math2;

public class StatusScreen implements Disposable, TextDest {
	private static final int[] PAL = { 0xffffffff, // 0: white
			0xffff0000, // 1: red
			0xff00ff00, // 2: green
			0xff0000ff, // 3: blue
			0xffffff00, // 4: yellow
			0xff00ffff // 5: cyan
	};

	private final Stack<PreText> unrendered = new Stack<PreText>();

	private final MultiDisposable md = new MultiDisposable();

	private final Font font;

	private final GraphicsContext gc;

	private int currentCol = Colours.WHITE;

	private int currentKern;

	private Component message;

	private MessageWriter topMw;

	private GridComponent activeGrid;

	private int gridPosX;

	private int gridPosY;

	private MessageWriter mw;

	class MessageWriter {
		private final ColComponent message;

		private RowComponent row;

		MessageWriter(int j) {
			message = new ColComponent(j);
			addRow();
		}

		private void addRow() {
			row = new RowComponent(Justify.SOUTH);
			message.add(row);
		}

		public void addTable(int w, int h) {
			GridComponent grid = new GridComponent(w, h);
			grid.setVerticalPadding(vScale(10));
			row.add(grid);
			gridOn(grid);
		}

		public void addText(String text) {
			if (text.length() != 0) {
				PreText p = new PreText(font, currentCol, currentKern, text);
				unrendered.add(p);
				row.add(p);
			}
		}

		public void addCr() {
			addAdv(25);
		}

		public void addParagraph() {
			addAdv(80);
		}

		public void addAdv(int size) {
			size = vScale(size);
			addRow();
			row.add(new SpacerComponent(0, size));
			addRow();
		}

		public Component getMessage() {
			return message;
		}
	}

	public StatusScreen(GraphicsContext gc, Font font) {
		this.gc = gc;
		this.font = font;
		topMw = mw = new MessageWriter(Justify.CENTRED);
	}

	@Override
	public void setCol(int v) {
		currentCol = PAL[v];
	}

	private int vScale(int size) {
		return Math2.fracMult(font.charHeight(), size, 50);
	}

	@Override
	public void setHorizontalPadding(int hp) {
		activeGrid.setHorizontalPadding(vScale(hp));
	}

	@Override
	public void setKern(int v) {
		currentKern = v;
	}

	public void done() {
		message = mw.getMessage();
	}

	boolean isReadyToDraw() {
		return unrendered.isEmpty();
	}

	private void getReadyToDraw() {
		if (isReadyToDraw()) return;
		PreText p = unrendered.pop();
		p.render();
		md.add(p);
	}

	void draw() {
		int w = message.width();
		int h = message.height();
		int x = (gc.screenWidth() - w) / 2;
		int y = (gc.screenHeight() - h) / 2;
		message.draw(x, y);
	}

	public void update() {
		getReadyToDraw();
		if (!isReadyToDraw()) return;
		draw();
	}

	@Override
	public void dispose() {
		md.dispose();
	}

	void gridOn(GridComponent grid) {
		activeGrid = grid;
		gridPosX = 0;
		gridPosY = 0;
		mw = new MessageWriter(Justify.WEST);
	}

	@Override
	public void endCell() {
		activeGrid.setContent(gridPosX, gridPosY, mw.getMessage());
		mw = new MessageWriter(Justify.WEST);
		gridPosX++;
		if (gridPosX == activeGrid.widthInCells()) {
			gridPosX = 0;
			gridPosY++;
			if (gridPosY == activeGrid.heightInCells()) {
				activeGrid = null;
				mw = topMw;
			}
		}
	}

	@Override
	public void addTable(int w, int h) {
		getMw().addTable(w, h);
	}

	@Override
	public void addText(String text) {
		getMw().addText(text);
	}

	@Override
	public void addCr() {
		getMw().addCr();
	}

	@Override
	public void addParagraph() {
		getMw().addParagraph();
	}

	@Override
	public void addAdv(int size) {
		getMw().addAdv(size);
	}

	private MessageWriter getMw() {
		return mw;
	}
}
