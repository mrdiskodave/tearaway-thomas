package com.nney.tt;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienWithLocation;
import com.nney.tt.aliens.LegacyAlien;
import com.nney.tt.geom.Coord;

public class AlienFactory {
	final private AlienInfoMap alienInfoMap;

	public AlienFactory(AlienInfoMap alienInfoMap) {
		this.alienInfoMap = alienInfoMap;
	}

	/**
	 * Legacy types that are now handled by a more general alien (rather than
	 * one of their own). Its loadFromLegacyData() knows what to do.
	 */
	private static final Map<Integer, String> LEGACY_ALIASES = new HashMap<>();

	/**
	 * Legacy types where the original had one object for each piece (each car
	 * of a Ferris wheel) and we have one for the whole thing: only the first
	 * one becomes an alien.
	 */
	private static final Set<Integer> LEGACY_MERGED = new HashSet<>();

	static {
		LEGACY_ALIASES.put(0, "plainLift"); // lift_alien: block lift, up and down
		LEGACY_ALIASES.put(54, "plainLift"); // ilift_alien: Iceland lift
		LEGACY_ALIASES.put(58, "trampoline"); // tram_alien: Iceland trampoline
		LEGACY_ALIASES.put(44, "ferrisWheel"); // feris_alien: Iceland Ferris wheel
		LEGACY_ALIASES.put(99, "trampoline"); // ftrmp_alien: Futureland trampoline
		LEGACY_MERGED.add(44);
		LEGACY_MERGED.add(32); // Fferis_alien: Futureland's Ferris wheel
	}

	private final Set<Integer> mergedSoFar = new HashSet<>();

	private String legacyName(int typeCode) {
		String alias = LEGACY_ALIASES.get(typeCode);
		if (alias != null) return alias;
		return AlienInfoMap.typeCodeToName(typeCode);
	}

	public Alien make(int typeCode, int x, int y, byte[] rest) {
		String tcName = legacyName(typeCode);
		Alien alien;
		if (alienInfoMap.nameExists(tcName)) {
			alien = alienInfoMap.instantiateAttach(alienInfoMap.getByName(tcName));
		}
		else {
			System.out.println("LEGACY ALIEN " + typeCode);
			alien = new LegacyAlien();
			alienInfoMap.attach(alien);
		}
		if (alien instanceof AlienWithLocation) {
			AlienWithLocation awl = (AlienWithLocation) alien;
			awl.c.x = x;
			awl.c.y = y;
		}
		else {
			// lifts and the like: tell them where the original object was
			alien.resetTo(new Coord(x, y));
		}
		alien.legacyData = rest;
		alien.loadFromLegacyData();
		return alien;
	}

	/**
	 * Turn a {@link LegacyAlien} (raw Amiga object data) into a proper alien,
	 * if there is now a class for its type.
	 * 
	 * @return The new alien, the one given if its type isn't ported yet, or
	 *         <code>null</code> if it has been absorbed into an alien already
	 *         made (see {@link #LEGACY_MERGED}).
	 */
	public Alien upgrade(LegacyAlien legacy) {
		byte[] data = legacy.getLegacyData();
		int typeCode = data[0] & 0xff;
		if (!alienInfoMap.nameExists(legacyName(typeCode))) return legacy;
		if (LEGACY_MERGED.contains(typeCode) && !mergedSoFar.add(typeCode)) {
			// part of something we've already made
			return null;
		}
		Coord c = legacy.getLocation();
		return make(typeCode, c.x, c.y, data);
	}

	public Alien make(String name) {
		return alienInfoMap.instantiateAttach(alienInfoMap.getByName(name));
	}

	public void wrapExisting(Alien alien) {
		alienInfoMap.attach(alien);
	}
}
