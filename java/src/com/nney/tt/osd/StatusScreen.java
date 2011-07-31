package com.nney.tt.osd;

import java.util.Stack;

import com.nney.tt.gfx.Colours;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.MultiDisposable;
import com.nney.utils.Math2;

public class StatusScreen implements Disposable, TextDest {
	private static final int[] PAL = { 0xffffffff, 0xffff0000, 0xff00ff00, 0xff0000ff, 0xffffff00, 0xff00ffff };

	private final Stack<PreText> unrendered = new Stack<PreText>();

	private final MultiDisposable md = new MultiDisposable();

	private final ColComponent message;

	private final GraphicsContext gc;

	private RowComponent row;

	private final Font font;

	private int currentCol = Colours.WHITE;

	private int currentKern;

	public StatusScreen(GraphicsContext gc, Font font) {
		this.gc = gc;
		this.font = font;
		message = new ColComponent();
		addRow();
	}

	private void addRow() {
		row = new RowComponent();
		message.add(row);
	}

	@Override
	public void addText(String text) {
		if (text.length()!=0) { 
			PreText p = new PreText(font, currentCol, currentKern, text);
			unrendered.add(p);
			row.add(p);
		}
	}
	
	@Override
	public void addCr() {
		addAdv(100);
	}
	
	@Override
	public void addParagraph() {
		addAdv(200);
	}

	@Override
	public void addAdv(int size) {
		size = Math2.fracMult(font.charHeight(), size, 100);
		addRow();
		row.add(new SpacerComponent(0, size));
		addRow();
	}
	
	
	@Override
	public void setCol(int v) {
		currentCol = PAL[v];
	}
	
	@Override
	public void setKern(int v) {
		currentKern = v;
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
}
