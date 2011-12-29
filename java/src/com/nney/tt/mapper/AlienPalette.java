package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.List;

import com.nney.tt.AlienInfo;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.CountingMap;
import com.nney.utils.ListUtil;
import com.nney.utils.SortKeyGenerator;

public class AlienPalette {
	class AnimAndPlayer {
		public final AnimPlayer animPlayer;
		public final Box box;

		public AnimAndPlayer(Anim anim) {
			this.animPlayer = new AnimPlayer();
			animPlayer.changeAnimation(anim);
			box = anim.box();
		}

		public Sprite nextFrame() {
			Sprite answer = animPlayer.nextFrame();
			if (animPlayer.hasAnimEnded()) animPlayer.rewind();
			return answer;
		}
	}

	private final HashMap<AlienInfo, AnimAndPlayer> animPlayers = new HashMap<AlienInfo, AnimAndPlayer>();

	private static final int ALIENS_TAB_BOX_RADIUS = 90;
	private static final int ALIENS_TAB_BOX_DIAMETER = ALIENS_TAB_BOX_RADIUS * 2 + 1;
	private static final int ALIENS_TAB_BOX_TEXT_GAP = -2;
	private static final int ALIENS_TAB_BOX_MARGIN = 5;

	private Carousel<AlienInfo> carousel;

	private final MapperGC mgc;

	private CountingMap<AlienInfo> census;

	private final List<AlienInfo> alienTypes;

	public AlienPalette(List<AlienInfo> alienTypes, MapperGC mgc, AnimsPool animsPool) {
		this.mgc = mgc;

		for (AlienInfo ai : alienTypes) {
			String a = ai.animsName();
			if (a != null) {
				animPlayers.put(ai, new AnimAndPlayer(animsPool.load(a).find(0)));
			}
		}
		this.carousel = new Carousel<AlienInfo>(alienTypes);
		this.alienTypes = alienTypes;
	}

	public void showAlienPalette() {
		int sx = mgc.screenWidth() / 2;
		int osy = mgc.screenHeight() / 2;

		Carousel<AlienInfo> c = carousel.copy();
		osy -= alienTabHeight(c.get());

		int sy = osy;
		while (sy < mgc.screenHeight()) {
			AlienInfo ai = c.get();
			drawAlienTab(sx, sy, ai, sy == osy);
			sy += alienTabHeight(ai);
			c.next();
		}

		sy = osy;
		c = carousel.copy();

		while (sy > 0) {
			c.prev();
			AlienInfo ai = c.get();
			sy -= alienTabHeight(ai);
			drawAlienTab(sx, sy, ai, false);
		}
	}

	private int alienTabHeight(AlienInfo ai) {
		return more() + graphicHeight(ai);
	}

	private int more() {
		return ALIENS_TAB_BOX_MARGIN * 2 + ALIENS_TAB_BOX_TEXT_GAP + mgc.charHeight();
	}

	private int graphicHeight(AlienInfo ai) {
		AnimAndPlayer animAndPlayer = animPlayers.get(ai);
		if (animAndPlayer == null) return 20;
		return animAndPlayer.box.height();
	}

	private void drawAlienTab(int sx, int sy, AlienInfo ai, boolean live) {
		if (live) {
			mgc.drawTransBox(sx - ALIENS_TAB_BOX_RADIUS, sy, ALIENS_TAB_BOX_DIAMETER, alienTabHeight(ai),
					mgc.process(0xff00ff00), 0xff0020ff);
		}

		int sp = graphicHeight(ai);
		AnimAndPlayer animAndPlayer = animPlayers.get(ai);
		if (animAndPlayer != null) {
			Sprite sprite = animAndPlayer.nextFrame();

			Box b = animAndPlayer.box;
			int cex = sx;
			int cey = sy + (sp + ALIENS_TAB_BOX_MARGIN) / 2;
			cex -= b.left;
			cey -= b.top;
			cex -= b.width() / 2;
			cey -= b.height() / 2;
			// mgc.fillRectangle(cex+b.left, cey+b.top, b.width(), b.height(),
			// 0xffff0000);
			sprite.drawByHandle(cex, cey, false);
		}

		String t = ai.name;
		int c = census.get(ai);
		if (c != 0) t += "(" + c + ")";
		mgc.drawText(sx - ALIENS_TAB_BOX_RADIUS + 5, sy + (sp + ALIENS_TAB_BOX_MARGIN + ALIENS_TAB_BOX_TEXT_GAP),
				0xffffff, t);

		if (!live) {
			mgc.drawTransBox(sx - ALIENS_TAB_BOX_RADIUS, sy, ALIENS_TAB_BOX_DIAMETER, alienTabHeight(ai), 0xff000000,
					0xb00020ff);
		}
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
		return carousel.get();
	}

	public void next() {
		carousel.next();
	}

	public void prev() {
		carousel.prev();
	}

	public void find(AlienInfo typeCode) {
		carousel.find(typeCode);
	}

	public void jumpTo(char c) {
		for (int x = 0; x < carousel.size(); x++) {
			carousel.next();
			if (get().name.charAt(0) == c) {
				return;
			}
		}
	}
}
