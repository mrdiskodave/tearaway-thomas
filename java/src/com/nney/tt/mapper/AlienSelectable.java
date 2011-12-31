package com.nney.tt.mapper;

import com.nney.tt.AlienInfo;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;

class AlienSelectable implements Selectable {
	private static final int ALIENS_TAB_BOX_RADIUS = 90;
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
			animBox = anim.getBounds();
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
	public Box getBounds() {
		return ourBox;
	}

	@Override
	public void draw(MapperGC mgc, Coord where) {
		int sx = where.x;
		int sy = where.y;

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