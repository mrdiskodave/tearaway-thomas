package com.nney.tt.mapper;

import java.nio.channels.SelectableChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.nney.tt.AlienInfo;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.CountingMap;
import com.nney.utils.ListUtil;
import com.nney.utils.SortKeyGenerator;

public class AlienPalette {
	static class AlienSelectable implements Selectable {
		private static final int ALIENS_TAB_BOX_RADIUS = 90;
		private static final int ALIENS_TAB_BOX_DIAMETER = ALIENS_TAB_BOX_RADIUS * 2 + 1;
		private static final int ALIENS_TAB_BOX_TEXT_GAP = -2;
		private static final int ALIENS_TAB_BOX_MARGIN = 5;

		final public AnimPlayer animPlayer;
		final public Box animBox;
		final private Box ourBox;
		private final String name;

		static AlienSelectable create(AlienInfo ai, AnimsPool pool, MapperGC mgc, Coord cursor) {
			String a = ai.animsName();
			AnimPlayer animPlayer = null;
			Box animBox = null;
			if (a != null) {
				Anim anim;
				anim = pool.load(a).find(0);
				animPlayer = new AnimPlayer();
				animPlayer.changeAnimation(anim);
				animBox = anim.box();
			}
			int ourHieght = ALIENS_TAB_BOX_MARGIN * 2 + ALIENS_TAB_BOX_TEXT_GAP + mgc.charHeight() + ourHeight(animBox);
			Box ourBox = Box.fromTopLeftAndSize(cursor, mgc.screenWidth(), ourHieght);
			cursor.y += ourHieght;
			return new AlienSelectable(animPlayer, animBox, ourBox, ai.name);
		}

		static private int ourHeight(Box animBox) {
			return animBox != null ? animBox.height() : 20;
		}

		AlienSelectable(AnimPlayer animPlayer, Box animBox, Box ourBox, String name) {
			this.animPlayer = animPlayer;
			this.animBox = animBox;
			this.ourBox = ourBox;
			this.name = name;
		}

		public Sprite nextFrame() {
			Sprite answer = animPlayer.nextFrame();
			if (animPlayer.hasAnimEnded()) animPlayer.rewind();
			return answer;
		}

		@Override
		public Box where() {
			return ourBox;
		}

		@Override
		public void draw(MapperGC mgc, Box where) {
			int sx = where.left;
			int sy = where.top;

			int sp = ourHeight(animBox);
			if (animPlayer != null) {
				Sprite sprite = animPlayer.nextFrame();

				Box b = animBox;
				int cex = sx;
				int cey = sy + (sp + ALIENS_TAB_BOX_MARGIN) / 2;
				cex -= b.left;
				cey -= b.top;
				cex -= b.width() / 2;
				cey -= b.height() / 2;
				// mgc.fillRectangle(cex+b.left, cey+b.top, b.width(),
				// b.height(),
				// 0xffff0000);
				sprite.drawByHandle(cex, cey, false);
			}

			// String t = ai.name;
			// int c = census.get(ai);
			// if (c != 0) t += "(" + c + ")";
			mgc.drawText(sx - ALIENS_TAB_BOX_RADIUS + 5, sy + (sp + ALIENS_TAB_BOX_MARGIN + ALIENS_TAB_BOX_TEXT_GAP),
					0xffffff, name);

		}
	}

	private static final int ALIENS_TAB_BOX_RADIUS = 90;
	private static final int ALIENS_TAB_BOX_DIAMETER = ALIENS_TAB_BOX_RADIUS * 2 + 1;
	private static final int ALIENS_TAB_BOX_TEXT_GAP = -2;
	private static final int ALIENS_TAB_BOX_MARGIN = 5;

	private final MapperGC mgc;

	private CountingMap<AlienInfo> census;

	private final List<AlienInfo> alienTypes;
	private SelectionScreen selectionScreen;

	public void start() {
		selectionScreen.start();
	}

	public void end() {
		selectionScreen.end();
	}

	public AlienPalette(List<AlienInfo> alienTypes, MapperGC mgc, MapperMousePosition mmp, AnimsPool animsPool) {
		this.mgc = mgc;

		ArrayList<Selectable> l = new ArrayList<Selectable>();
		Coord cursor = new Coord(0, 0);
		for (AlienInfo ai : alienTypes) {
			l.add(AlienSelectable.create(ai, animsPool, mgc, cursor));
		}
		this.alienTypes = alienTypes;
		this.selectionScreen = new SelectionScreen(mgc, mmp, l);
	}

	public void draw() {
		selectionScreen.draw();
	}

	public void sendCenus(CountingMap<AlienInfo> c) {
		this.census = c;
		ListUtil.sort(alienTypes, new SortKeyGenerator<AlienInfo, String>() {
			@Override
			public String gen(AlienInfo t) {
				return t.name;
				// // Order first by quantity and then by name.
				// //
				// // one could make a nice Comparable class but this hack works
				// // just as well...
				// return String.format("%08d%s", 99999999 - census.get(t),
				// t.name);
			}
		});
	}

	public AlienInfo get() {
		return alienTypes.get(0);
	}

	public void next() {
		// carousel.next();
	}

	public void prev() {
		// carousel.prev();
	}

	public void find(AlienInfo typeCode) {
		// carousel.find(typeCode);
	}

	// public void jumpTo(char c) {
	// for (int x = 0; x < carousel.size(); x++) {
	// carousel.next();
	// if (get().name.charAt(0) == c) {
	// return;
	// }
	// }
	// }
}
