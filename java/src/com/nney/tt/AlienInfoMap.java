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
	 * Various indexes that all ignore aliens that are not available according
	 * to {@link TTResource#spriteExists(String)}.
	 */
	private final Map<String, AlienInfo> nameToAlienInfo = new HashMap<String, AlienInfo>();
	private final Map<Class<? extends Alien>, AlienInfo> classToAlienInfo = new HashMap<Class<? extends Alien>, AlienInfo>();
	private final Map<Class<? extends Alien>, Integer> classUseCount = new HashMap<Class<? extends Alien>, Integer>();

	private final List<String> names = new ArrayList<String>();
	private final List<String> animList = new ArrayList<String>();

	private String worldName;
	

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
		this.worldName = worldName;
		nameToAlienInfo.clear();
		classToAlienInfo.clear();
		classUseCount.clear();
		names.clear();
		animList.clear();

		for (AlienInfo ai : aim) {
			if (ai.setWorld(worldName)) {
				classToAlienInfo.put(ai.alienClass, ai);

				Integer useCount = classUseCount.get(ai.alienClass);
				if (useCount == null) useCount = 0;
				useCount++;
				classUseCount.put(ai.alienClass, useCount);

				if (!ai.internal()) {
					addToIndex(ai, ai.name);
					addToIndex(ai, typeCodeToName(ai.typeCode));

					assert !names.contains(ai.name);
					names.add(ai.name);
				}

				String name = ai.animsName();
				if (name != null) {
					assert !animList.contains(name);
					animList.add(name);
				}
			}
		}
		Collections.sort(names);
		Collections.sort(animList);
	}
	
	String getWorld() {
		return worldName;
	}

	private void addToIndex(AlienInfo ai, String k) {
		assert !nameToAlienInfo.containsKey(k);
		nameToAlienInfo.put(k, ai);
	}

	public void collectPreloadNames(Set<String> names) {
		for (AlienInfo ai : aim) {
			if (ai.internal() && ai.animsName() != null) {
				names.add(ai.animsName());
			}
		}
	}

	private AlienInfo getByClass(Class<? extends Alien> c) {
		// it's a problem if we cannot give an unambiguous answer
		Integer cuc = classUseCount.get(c);
		int icuc = cuc == null ? 0 : cuc;
		if (icuc != 1) {
			throw new RuntimeException("Class count is " + icuc + " for " + c);
		}
		return classToAlienInfo.get(c);
	}

	/**
	 * There are two ways to make a correctly wired up {@link Alien}. 1) use
	 * {@link AlienInfo#instantiateAttach()} 2) Construct it with <code>new</code>
	 * then pass it here.
	 * 
	 * @param alien
	 *            The {@link Alien} that you just constructed.
	 */
	public void attach(Alien alien) {
		alien.attach(getByClass(alien.getClass()));
	}

	/**
	 * @return A read only list of all the alien names available.
	 */
	public List<String> queryNames() {
		return names;
	}

	/**
	 * @return A read only list of all the anims we'll ever need.
	 */
	public List<String> queryAnimList() {
		return animList;
	}

	// public void dump() {
	// StringBuffer sb = new StringBuffer();
	// for (int tc : typeCodes) {
	// if (sb.length() != 0) sb.append(',');
	// sb.append(tc);
	// }
	// System.out.println(sb);
	// }

	public boolean nameExists(String name) {
		return nameToAlienInfo.containsKey(name);
	}

	public AlienInfo getByName(String name) {
		AlienInfo answer = nameToAlienInfo.get(name);
		if (answer == null) throw new RuntimeException("Alien name " + name + " not present");
		return answer;
	}

	static String typeCodeToName(int typeCode) {
		return AlienInfo.makeInternalName("tc" + typeCode);
	}
}
