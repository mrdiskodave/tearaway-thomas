package com.nney.tt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienInfoAnn;
import com.nney.tt.aliens.AlienInfoAnns;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;

public class AlienInfoMap {
	private final Map<Integer, AlienInfo> typeToAlienInfo = new HashMap<Integer, AlienInfo>();
	private final Map<Class<? extends Alien>, AlienInfo> classToAlienInfo = new HashMap<Class<? extends Alien>, AlienInfo>();
	private final Map<Class<? extends Alien>, Integer> classUseCount = new HashMap<Class<? extends Alien>, Integer>();
	private final ArrayList<Integer> typeCodes = new ArrayList<Integer>();
	
	private final List<AlienInfo> aim = new ArrayList<AlienInfo>();

	void add(AlienInfo a) {
		typeToAlienInfo.put(a.typeCode, a);
		classToAlienInfo.put(a.alienClass, a);
		aim.add(a);

		Integer useCount = classUseCount.get(a.alienClass);
		if (useCount == null) useCount = 0;
		useCount++;
		classUseCount.put(a.alienClass, useCount);
		if (a.typeCode>=0) {
			typeCodes.add(a.typeCode);
		}
		
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
	
	public List<Integer> getTypeCodes() {
		Collections.sort(typeCodes);
		return typeCodes;
	}

	public void addAnn(Class<? extends Alien> c) {
		AlienInfoAnns a = c.getAnnotation(AlienInfoAnns.class);
		if (a!=null) {
			addAnn(c, a);
		}
		AlienInfoAnn b = c.getAnnotation(AlienInfoAnn.class);
		if (b!=null) {
			addAnn(c, b);
		}
	}

	private void addAnn(Class<? extends Alien> c, AlienInfoAnns a) {
		for (AlienInfoAnn v: a.value()) {
			addAnn(c, v);
		}
	}

	private void addAnn(Class<? extends Alien> c, AlienInfoAnn a) {
		add(new AlienInfo(a.type(), a.gfx(), c));
	}
}
