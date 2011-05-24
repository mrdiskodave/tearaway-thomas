package com.nney.tt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nney.tt.aliens.Alien;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;

public class AlienInfoMap {
	private final Map<Integer, AlienInfo> typeToAlienInfo = new HashMap<Integer, AlienInfo>();
	private final Map<Class<? extends Alien>, AlienInfo> classToAlienInfo = new HashMap<Class<? extends Alien>, AlienInfo>();
	private final Map<Class<? extends Alien>, Integer> classUseCount = new HashMap<Class<? extends Alien>, Integer>();
	
	private final List<AlienInfo> aim = new ArrayList<AlienInfo>();

	void add(AlienInfo a) {
		typeToAlienInfo.put(a.typeCode, a);
		classToAlienInfo.put(a.alienClass, a);
		aim.add(a);

		Integer useCount = classUseCount.get(a.alienClass);
		if (useCount == null) useCount = 0;
		useCount++;
		classUseCount.put(a.alienClass, useCount);
//		System.out.println("Adding "+a.alienClass+" new use count is "+useCount);
	}

	public void doPreLoad(AnimsPool animsPool) {
		for (AlienInfo a : aim) {
			// if it doesn't have an id that is because it
			// doesn't occur in any map but is instead deployed live at runtime
			if (a.typeCode < 0) {
				// so preload its graphics now
				animsPool.load(a.animsName);
			}
		}
	}

	public AlienInfo getByType(int type) {
		return typeToAlienInfo.get(type);
	}

	void removeByType(int type) {
		typeToAlienInfo.remove(type);
	}

	public AlienInfo getByClass(Class<? extends Alien> c) {
		// it's a problem if we cannot give an unambiguous answer
		Integer cuc = classUseCount.get(c);
		if (cuc==null || cuc!=1) {
			throw new RuntimeException("Class count is "+cuc+" for "+c);
		}
		return classToAlienInfo.get(c);
	}

	public void giveTypeCodeAndConnectAnims(Alien c, AnimsPool animsPool) {
		AlienInfo ai = getByClass(c.getClass());
		c.typeCode = ai.typeCode;
		if (ai.animsName != null) {
			Anims anims = animsPool.directGet(ai.animsName);
			assert anims != null : "need to preload " + ai.animsName;
			c.connectAnims(anims);
		}
	}

	public void clear() {
		assert false;
		typeToAlienInfo.clear();
		classToAlienInfo.clear();
		classUseCount.clear();
	}
}
