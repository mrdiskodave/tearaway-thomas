package com.nney.tt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nney.tt.aliens.Alien;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;

public class AlienInfoMap {
	Map<Integer, AlienInfo> typeToAlienInfo = new HashMap<Integer, AlienInfo>();
	Map<Class<? extends Alien>, AlienInfo> classToAlienInfo = new HashMap<Class<? extends Alien>, AlienInfo>();
	Map<Class<? extends Alien>, Integer> classUseCount = new HashMap<Class<? extends Alien>, Integer>();
	private AnimsPool animsPool;

	public AlienInfoMap(AnimsPool animsPool) {
		this.animsPool = animsPool;
	}

	void add(AlienInfo a) {
		typeToAlienInfo.put(a.id, a);
		classToAlienInfo.put(a.alienClass, a);

		Integer useCount = classUseCount.get(a.alienClass);
		if (useCount == null) useCount = 0;
		classUseCount.put(a.alienClass, useCount + 1);
		
		// if it doesn't have an id that is because it
		// doesn't occur in any map but is instead deployed live at runtime
		if (a.id<0) {
			// so preload its graphics now
			animsPool.load(a.animsName);
		}
	}

	public AlienInfo getByType(int type) {
		return typeToAlienInfo.get(type);
	}

	public AlienInfo getByClass(Class<? extends Alien> c) {
		return classToAlienInfo.get(c);
	}

	public void connectAnims(Alien c) {
		assert classUseCount.get(c.getClass()) == 1;
		// class is used with many animation names so how
		// do we know which to give it???

		AlienInfo ai = getByClass(c.getClass());
		if (ai.animsName != null) {
			System.out.println(c.getClass() + " gets " + ai.animsName);
			Anims anims = animsPool.directGet(ai.animsName);
			assert anims!=null : "need to preload "+ai.animsName;
			c.connectAnims(anims);
		}
	}

	public void clear() {
		typeToAlienInfo.clear();
		classToAlienInfo.clear();
		classUseCount.clear();
	}
}
