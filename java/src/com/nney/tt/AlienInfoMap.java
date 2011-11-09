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
import com.nney.tt.aliens.ArrowAlien;
import com.nney.tt.aliens.BatAlien;
import com.nney.tt.aliens.BearAlien;
import com.nney.tt.aliens.BeeAlien;
import com.nney.tt.aliens.BirdAlien;
import com.nney.tt.aliens.Bird2Alien;
import com.nney.tt.aliens.ClockAlien;
import com.nney.tt.aliens.DebugTextAlien;
import com.nney.tt.aliens.ExitAlien;
import com.nney.tt.aliens.ExtraLifeAlien;
import com.nney.tt.aliens.FallingAlien;
import com.nney.tt.aliens.FlameAlien;
import com.nney.tt.aliens.FloorFailureAlien;
import com.nney.tt.aliens.GemAlien;
import com.nney.tt.aliens.GhostAlien;
import com.nney.tt.aliens.HiddenScoreGiftAlien;
import com.nney.tt.aliens.LegacyAlien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.MapBoundsAlien;
import com.nney.tt.aliens.PlainLiftAlien;
import com.nney.tt.aliens.PlayerAlien;
import com.nney.tt.aliens.PortraitAlien;
import com.nney.tt.aliens.ScoreCollectableAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.aliens.ShieldAlien;
import com.nney.tt.aliens.SineLiftAlien;
import com.nney.tt.aliens.SpikeAlien;
import com.nney.tt.aliens.SpriteAlien;
import com.nney.tt.aliens.StarAlien;
import com.nney.tt.aliens.StopAlien;
import com.nney.tt.aliens.TeleportAlien;
import com.nney.tt.aliens.TrampolineAlien;
import com.nney.tt.aliens.WingsAlien;
import com.nney.tt.aliens.WobbleGemAlien;
import com.nney.tt.aliens.YellowBirdAlien;
import com.nney.tt.resources.TTResource;
import com.nney.utils.CountingMap;

public class AlienInfoMap {
	/**
	 * Full list of {@link AlienInfo}s.
	 */
	private final List<AlienInfo> aim = new ArrayList<AlienInfo>();
	
	private final List<AlienInfo> present = new ArrayList<AlienInfo>();

	/**
	 * Various indexes that all ignore aliens that are not available according
	 * to {@link TTResource#spriteExists(String)}.
	 */
	private final Map<String, AlienInfo> nameToAlienInfo = new HashMap<String, AlienInfo>();
	private final Map<Class<? extends Alien>, AlienInfo> classToAlienInfo = new HashMap<Class<? extends Alien>, AlienInfo>();
	private final CountingMap<Class<? extends Alien>> classUseCount = new CountingMap<Class<? extends Alien>>(); 

	private final List<String> animList = new ArrayList<String>();

	private String worldName;
	
	public AlienInfoMap(String worldName) {
		add(new AlienInfo(4, "exit", "0exit", ExitAlien.class));
		add(new AlienInfo(5, "shield", "0shld", ShieldAlien.class));
		add(new AlienInfo(7, "clock", "0clok", ClockAlien.class));
		add(new AlienInfo(12, "teleport", "0tele", TeleportAlien.class));
		add(new AlienInfo(22, "extraLife", "0life", ExtraLifeAlien.class));
		add(new AlienInfo(14, "wings", "0wing", WingsAlien.class));
		add(new AlienInfo(15, "floorFailure", null, FloorFailureAlien.class)); // special1
		// for w6.map
		add(new AlienInfo(34, "hiddenScoreGift", null, HiddenScoreGiftAlien.class));
		add(new AlienInfo(36, "bear", "?bear", BearAlien.class));
		add(new AlienInfo(37, "bat", "gbatt", BatAlien.class));
		add(new AlienInfo(39, "spike", "gspik", SpikeAlien.class));
		add(new AlienInfo(48, "ghost", "gghst", GhostAlien.class));
		add(new AlienInfo(63, "bee", "wabee", BeeAlien.class));
		add(new AlienInfo(72, "sineLift", "wlog0", SineLiftAlien.class));
		add(new AlienInfo(73, "trampoline", "wtrmp", TrampolineAlien.class));
		add(new AlienInfo(74, "yellowBird", "wybrd", YellowBirdAlien.class));
		add(new AlienInfo(55, "bird", "?bird", BirdAlien.class)); // poly
		add(new AlienInfo(204, "bird2", "?bird", Bird2Alien.class)); // poly
		add(new AlienInfo(57, "penguin", "ipeng", BearAlien.class));
		// add(new AlienInfo(78, null, ScreenLimiterAlien.class));
		add(new AlienInfo(95, "star", "0star", StarAlien.class));
		add(new AlienInfo(13, "stop", "0stop", StopAlien.class));

		add(new AlienInfo(200, "plainLift", "?lift", PlainLiftAlien.class));
		add(new AlienInfo(201, "player", "0tt", PlayerAlien.class));
		add(new AlienInfo(202, "mapBounds", null, MapBoundsAlien.class));
		add(new AlienInfo(203, "legacy", null, LegacyAlien.class));

		// use of annotations to make this easier
		addFromAnnotation(FlameAlien.class);
		addFromAnnotation(WobbleGemAlien.class);
		addFromAnnotation(GemAlien.class);
		addFromAnnotation(ArrowAlien.class);
		addFromAnnotation(PortraitAlien.class);
		addFromAnnotation(SpriteAlien.class);
		addFromAnnotation(ScoreCollectableAlien.class);

		// internal things
		// * no typeCode
		// * a name that cannot be used to look it up
		// * only one instance
		// * can only be looked up by className
		// * do not appear in load and save images
		add(new AlienInfo(-1, AlienInfo.makeInternalName("text"), null, DebugTextAlien.class));
		add(new AlienInfo(-1, AlienInfo.makeInternalName("score"), "0scor", ScoreNoticeAlien.class));
		add(new AlienInfo(-1, AlienInfo.makeInternalName("magic"), "0magc", MagicDustAlien.class));
		add(new AlienInfo(-1, AlienInfo.makeInternalName("fall"), null, FallingAlien.class));

		setWorld(worldName);
	}

	private void add(AlienInfo a) {
		aim.add(a);
	}

	private void addFromAnnotation(Class<? extends Alien> c) {
		AlienInfoAnns a = c.getAnnotation(AlienInfoAnns.class);
		if (a != null) {
			addFromAnnotation(c, a);
		}
		AlienInfoAnn b = c.getAnnotation(AlienInfoAnn.class);
		if (b != null) {
			addFromAnnotation(c, b);
		}
	}

	private void addFromAnnotation(Class<? extends Alien> c, AlienInfoAnns a) {
		for (AlienInfoAnn v : a.value()) {
			addFromAnnotation(c, v);
		}
	}

	private void addFromAnnotation(Class<? extends Alien> c, AlienInfoAnn a) {
		add(new AlienInfo(a.type(), a.name(), a.gfx(), a.score(), c));
	}

	private void setWorld(String worldName) {
		this.worldName = worldName;
		nameToAlienInfo.clear();
		classToAlienInfo.clear();
		classUseCount.clear();
		animList.clear();
		present.clear();

		for (AlienInfo ai : aim) {
			if (ai.setWorld(worldName)) {
				classToAlienInfo.put(ai.alienClass, ai);

				classUseCount.inc(ai.alienClass);
				if (!ai.internal()) {
					addToIndex(ai, ai.name);
					addToIndex(ai, typeCodeToName(ai.typeCode));
				}

				String name = ai.animsName();
				if (name != null) {
					// TODO: why not use a Set?
					if (!animList.contains(name)) animList.add(name);
				}
				
				present.add(ai);
				
			}
			
		}
		Collections.sort(animList);
	}
	
	public String getName() {
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
		if (classUseCount.get(c) != 1) {
			throw new RuntimeException("Class count is " + classUseCount.get(c) + " for " + c);
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
	
	public ArrayList<AlienInfo> getExternal() {
		ArrayList<AlienInfo> answer = new ArrayList<AlienInfo>();
		for (AlienInfo ai: present) {
			if (!ai.internal()) answer.add(ai);
		}
		return answer;
	}
}
