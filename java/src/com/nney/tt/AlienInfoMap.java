package com.nney.tt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienInfoAnn;
import com.nney.tt.aliens.AlienInfoAnns;
import com.nney.tt.resources.TTResource;

public class AlienInfoMap {
	/**
	 * Full list of {@link AlienInfo}s.
	 */
	private final List<AlienInfo> aim = new ArrayList<AlienInfo>();


	/**
	 * Various indexes that all ignore aliens that are not available according to
	 * {@link TTResource#spriteExists(String)}. 
	 */
	private final Map<Integer, AlienInfo> typeToAlienInfo = new HashMap<Integer, AlienInfo>();
	private final Map<String, AlienInfo> nameToAlienInfo = new HashMap<String, AlienInfo>();
	private final Map<Class<? extends Alien>, AlienInfo> classToAlienInfo = new HashMap<Class<? extends Alien>, AlienInfo>();
	private final Map<Class<? extends Alien>, Integer> classUseCount = new HashMap<Class<? extends Alien>, Integer>();
	private final List<Integer> typeCodes = new ArrayList<Integer>();
	private final List<String> animList = new ArrayList<String>(); 

	void add(AlienInfo a) {
		aim.add(a);
		// System.out.println("Adding "+a.alienClass+" new use count is "+useCount);
	}

	public void addAnn(Class<? extends Alien> c) {
		AlienInfoAnns a = c.getAnnotation(AlienInfoAnns.class);
		if (a != null) {
			addAnn(c, a);
		}
		AlienInfoAnn b = c.getAnnotation(AlienInfoAnn.class);
		if (b != null) {
			addAnn(c, b);
		}
	}

	private void addAnn(Class<? extends Alien> c, AlienInfoAnns a) {
		for (AlienInfoAnn v : a.value()) {
			addAnn(c, v);
		}
	}

	private void addAnn(Class<? extends Alien> c, AlienInfoAnn a) {
		add(new AlienInfo(a.type(), a.name(), a.gfx(), a.score(), c));
	}

	public void setWorld(String worldName) {
		typeToAlienInfo.clear();
		classToAlienInfo.clear();
		classUseCount.clear();
		typeCodes.clear();
		animList.clear();

		for (AlienInfo ai : aim) {
			if (ai.setWorld(worldName)) {
				classToAlienInfo.put(ai.alienClass, ai);
	
				Integer useCount = classUseCount.get(ai.alienClass);
				if (useCount == null) useCount = 0;
				useCount++;
				classUseCount.put(ai.alienClass, useCount);
	
				if (ai.typeCode >= 0) {
					assert !typeToAlienInfo.containsKey(ai.typeCode);
					typeToAlienInfo.put(ai.typeCode, ai);
					typeCodes.add(ai.typeCode);

					assert !nameToAlienInfo.containsKey(ai.name);
					nameToAlienInfo.put(ai.name, ai);
				}
				
				String name = ai.animsName();
				if (name!=null) {
					animList.add(name);
				}
			}
		}
		Collections.sort(typeCodes);
		Collections.sort(animList);
	}
	
	public void collectPreloadNames(Set<String> names) {
		for (AlienInfo ai : aim) {
			if (ai.typeCode < 0) {
				names.add(ai.animsName());
			}
		}
	}

	public AlienInfo getByClass(Class<? extends Alien> c) {
		// it's a problem if we cannot give an unambiguous answer
		Integer cuc = classUseCount.get(c);
		if (cuc == null || cuc != 1) {
			throw new RuntimeException("Class count is " + cuc + " for " + c);
		}
		return classToAlienInfo.get(c);
	}

	/**
	 * @return A read only list of all the typeCodes available.
	 */
	public List<Integer> getTypeCodes() {
		return typeCodes;
	}

	/**
	 * @return A read only list of all the anims we'll ever need.
	 */
	public List<String> getAnimList() {
		return animList;
	}

	public void dump() {
		StringBuffer sb = new StringBuffer();
		for (int tc : typeCodes) {
			if (sb.length() != 0) sb.append(',');
			sb.append(tc);
		}
		System.out.println(sb);
	}
	
	public AlienInfo getByType(int type) {
		return typeToAlienInfo.get(type);
	}

	void hideByType(int type) {
		// we just unindex it
		typeToAlienInfo.remove(type);
	}

}
