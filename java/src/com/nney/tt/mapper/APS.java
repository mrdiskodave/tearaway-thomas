package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.SimpleDataDestination;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;

/**
 * Alien Property Services.
 */
public class APS {
	
	//
	// alien specific
	//
	
	public static void moveAlienAbsolute(Alien a, Coord pos) {
		Coord diff = pos.sub2(a.getLocation());
		moveAlienRelative(a, diff);
	}

	public static void moveAlienRelative(Alien a, Coord delta) {
		List<Prop> props = OPS.propsFor(a);
		for (Prop prop : props) {
			prop.moveBy(delta);
		}
	}
	
	private static class AlienKey implements Comparable<AlienKey> {
		public final Alien alien;
		public final String key;

		AlienKey(Alien a) {
			this.alien = a;
			DataDestination dd = new SimpleDataDestination();
			dd.write(a.alienInfo.name);
			OPS.saveProps(a, dd);
			key = dd.toString();
		}

		@Override
		public int compareTo(AlienKey other) {
			return key.compareTo(other.key);
		}

		@Override
		public boolean equals(Object other) {
			return compareTo((AlienKey) other) == 0;
		}
	}

	/**
	 * Order a list of aliens in some approximately stable way. This is intended
	 * to be used before saving the aliens to avoid thrashing the version
	 * control system with unreadable deltas. It isn't fast.
	 */
	public static void orderAlienList(ArrayList<Alien> al) {
		ArrayList<AlienKey> akl = new ArrayList<AlienKey>();
		for (Alien a : al) {
			akl.add(new AlienKey(a));
		}
		Collections.sort(akl);
		al.clear();
		for (AlienKey ak : akl) {
			al.add(ak.alien);
		}
	}
}
