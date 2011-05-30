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

// alien property services
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

	public static void copyProps(Alien src, final Alien dest) {
		List<Prop> destProps = APS.propsForAlien(dest);
		List<Prop> srcProps = APS.propsForAlien(src);
		assert srcProps.size() == destProps.size();
		for (int x = 0; x < srcProps.size(); x++) {
			destProps.get(x).copyFrom(srcProps.get(x));
		}
	}

	public static void moveProps(Alien dest, Coord diff) {
		List<Prop> zps = APS.propsForAlien(dest);
		for (Prop zp: zps) {
			zp.moveBy(diff);
		}
		dest.onPropUpdate();
	}

}
