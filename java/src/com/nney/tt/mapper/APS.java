package com.nney.tt.mapper;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;
import com.nney.tt.aliens.AlienWithGeneratedLocation;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class APS {
	static List<Prop> propsForAlien(Alien alien) {
		assert alien != null;
		List<Prop> props = new ArrayList<Prop>();
		Field[] fields = alien.getClass().getFields();
		for (Field field : fields) {
			AlienProp p = field.getAnnotation(AlienProp.class);
			if (p != null && !(p.xtraDef().equals("location") && alien instanceof AlienWithGeneratedLocation)) {
				Prop prop = null;
				PropPack pp = new PropPack(alien, field);
				Class<?> ft = field.getType();

				if (ft == Box.class) {
					prop = new BoxVisualProp(pp);
				}
				else if (ft == XRange.class) {
					prop = new XRangeVisualProp(pp);
				}
				else if (ft == Coord.class) {
					prop = new CoordVisualProp(pp);
				}
				else if (ft == boolean.class) {
					prop = new BooleanProp(pp);
				}
				else {
					System.out.println(ft);
					assert false;
				}
				assert prop != null;
				props.add(0, prop);
			}
		}
		return props;
	}

}
