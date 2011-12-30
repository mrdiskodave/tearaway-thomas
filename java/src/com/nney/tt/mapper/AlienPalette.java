package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.AlienInfo;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.ListUtil;
import com.nney.utils.SortKeyGenerator;

public class AlienPalette {
	private final MapperGC mgc;

	private final List<AlienInfo> alienTypes;
	private SelectionScreen selectionScreen;

	private Coord animateHere;

	private AnimPlayer ap = new AnimPlayer();

	private final AnimsPool animsPool;

	private int width;

	public void begin() {
		selectionScreen.begin();
	}

	public void end() {
		selectionScreen.end();
	}

	public AlienPalette(List<AlienInfo> alienTypes, MapperGC mgc, SimpleMouse simpleMouse, AnimsPool animsPool) {
		this.mgc = mgc;
		this.animsPool = animsPool;

		int h = mgc.charHeight() + 4;
		int c = 0;

		ListUtil.sort(alienTypes, new SortKeyGenerator<AlienInfo, String>() {
			@Override
			public String gen(AlienInfo t) {
				return nameFromAi(t);
			}
		});

		int w = 0;
		for (AlienInfo ai : alienTypes) {
			w = Math.max(w, nameFromAi(ai).length());
		}
		w *= mgc.charWidth();
		w += 4;

		animateHere = new Coord(w + (mgc.screenWidth() - w) / 2, mgc.screenHeight() / 2);
		width = w;

		ArrayList<Selectable> l = new ArrayList<Selectable>();
		for (AlienInfo ai : alienTypes) {
			Box b = Box.fromTopLeftAndSize(0, c, w, h);
			l.add(new TextSelectable(b, nameFromAi(ai)));
			c += h;
		}

		this.alienTypes = alienTypes;
		this.selectionScreen = new SelectionScreen(mgc, simpleMouse, l);
	}

	public String nameFromAi(AlienInfo ai) {
		return ai.name;
	}

	public void draw() {
		selectionScreen.draw();
		mgc.fillRectangle(width, 0, 1, 1000, 0xff0000ff);
		int j = selectionScreen.getHover();
		AlienInfo ai = alienTypes.get(j);
		String name = ai.animsName();
		if (name != null) {
			ap.changeAnimation(animsPool.expect(name).find(0));
			Sprite sprite = ap.nextFrame();
			sprite.drawByHandle(animateHere.x, animateHere.y, false);
		}
	}

	// public void sendCenus(CountingMap<AlienInfo> c) {
	// this.census = c;
	// ListUtil.sort(alienTypes, new SortKeyGenerator<AlienInfo, String>() {
	// @Override
	// public String gen(AlienInfo t) {
	// return nameFromAi(t);
	// // // Order first by quantity and then by name.
	// // //
	// // // one could make a nice Comparable class but this hack works
	// // // just as well...
	// // return String.format("%08d%s", 99999999 - census.get(t),
	// // t.name);
	// }
	// });
	// }

	public AlienInfo get() {
		return alienTypes.get(selectionScreen.getHover());
	}

	public void moveBy(int d) {
		selectionScreen.moveBy(d);
	}

	public void find(AlienInfo typeCode) {
		for (int x = 0; x < alienTypes.size(); x++) {
			if (alienTypes.get(x) == typeCode) {
				selectionScreen.setHover(x);
			}
		}
	}

	public void jumpTo(char c) {
		for (int x = 1; x < alienTypes.size(); x++) {
			int h = selectionScreen.getHoverRel(x);
			if (alienTypes.get(h).name.charAt(0) == c) {
				selectionScreen.setHover(h);
				break;
			}
		}
	}
}
