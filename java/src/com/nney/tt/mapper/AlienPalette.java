package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.HashMap;

import com.nney.tt.AlienInfo;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.AnimPlayer;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.CountingMap;

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

	private TypeCodeTabber<AlienInfo> alienTabber;

	private final MapperGC mgc;

	private final CountingMap<AlienInfo> survey;

	
	public AlienPalette(ArrayList<AlienInfo> ais, MapperGC mgc, AnimsPool animsPool, CountingMap<AlienInfo> census) {
		this.mgc = mgc;
		this.survey = census;

		for (AlienInfo ai: ais) {
			if (ai.animsName()!=null) {
				animPlayers.put(ai, new AnimAndPlayer(animsPool.load(ai.animsName()).find(0)));
			}
		}
		this.alienTabber = new TypeCodeTabber<AlienInfo>(ais);
	}

	public void showAlienPalette() {
		int sx = mgc.screenWidth() / 2;
		int osy = mgc.screenHeight() / 2;

		TypeCodeTabber<AlienInfo> at = alienTabber.copy();
		osy -= alienTabHeight(at.get())/2;

		int sy = osy;
		while (sy<mgc.screenHeight()) {
			AlienInfo ai = at.get();
			int h = alienTabHeight(ai);
			drawAlienTab(sx, sy, ai, sy==osy);
			sy += h;
			at.next();
		}
		
		sy = osy;
		at = alienTabber.copy();

		while (sy>0) {
			at.prev();
			AlienInfo ai = at.get();
			int h = alienTabHeight(ai);
			sy -= h;
			drawAlienTab(sx, sy, ai, false);
		}
	}
	
	private int alienTabHeight(AlienInfo ai) {
		return more()+graphicHeight(ai);
	}

	private int more() {
		return ALIENS_TAB_BOX_MARGIN*2  + ALIENS_TAB_BOX_TEXT_GAP + mgc.charHeight();
	}

	private int graphicHeight(AlienInfo ai) {
		AnimAndPlayer animAndPlayer = animPlayers.get(ai);
		if (animAndPlayer==null) return 20;
		return animAndPlayer.box.height();
	}
	
	private void drawAlienTab(int sx, int sy, AlienInfo ai, boolean live) {
		if (live) {
			mgc.drawTransBox(sx - ALIENS_TAB_BOX_RADIUS, sy, ALIENS_TAB_BOX_DIAMETER,
				alienTabHeight(ai), mgc.process(0xff00ff00), 0xff0020ff);
		}

		int sp = graphicHeight(ai);
		AnimAndPlayer animAndPlayer = animPlayers.get(ai);
		if (animAndPlayer!=null) {
			Sprite sprite = animAndPlayer.nextFrame();

			Box b = animAndPlayer.box;
			int cex = sx;
			int cey = sy + (sp+ALIENS_TAB_BOX_MARGIN)/2;
			cex -= b.left;
			cey -= b.top;
			cex -= b.width()/2;
			cey -= b.height()/2;
			// mgc.fillRectangle(cex+b.left, cey+b.top, b.width(), b.height(), 0xffff0000);
			sprite.drawByHandle(cex, cey, false);
		}

		String t = ai.name;
		int c = survey.get(ai);
		if (c!=0) t += "("+c+")";
		mgc.drawText(sx - ALIENS_TAB_BOX_RADIUS + 5, sy + (sp+ALIENS_TAB_BOX_MARGIN+ALIENS_TAB_BOX_TEXT_GAP), 0x80ffff, t);
		
		if (!live) {
			mgc.drawTransBox(sx - ALIENS_TAB_BOX_RADIUS, sy, ALIENS_TAB_BOX_DIAMETER,
				alienTabHeight(ai), 0xff000000, 0xb00020ff);
		}
	}

	public AlienInfo get() {
		return alienTabber.get();
	}
	
	public void next() {
		alienTabber.next();
	}

	public void prev() {
		alienTabber.prev();
	}

	public void find(AlienInfo typeCode) {
		alienTabber.find(typeCode);
	}
}
