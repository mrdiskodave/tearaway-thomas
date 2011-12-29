package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.SimpleDataDestination;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.OPS;
import com.nney.tt.props.Prop;
import com.nney.utils.ListUtil;
import com.nney.utils.SortKeyGenerator;

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

	/**
	 * Order a list of aliens in some approximately stable way. This is intended
	 * to be used before saving the aliens to avoid thrashing the version
	 * control system with unreadable deltas. It isn't fast.
	 */
	public static void orderAlienList(ArrayList<Alien> al) {
		ListUtil.sort(al, new SortKeyGenerator<Alien, String>() {
			@Override
			public String gen(Alien t) {
				DataDestination dd = new SimpleDataDestination();
				dd.write(t.alienInfo.name);
				OPS.saveProps(t, dd);
				return dd.toString();
			}
		});
	}
}
