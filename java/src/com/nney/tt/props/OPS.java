package com.nney.tt.props;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

/**
 * Object Property Services.
 */
public class OPS {
	public static List<Prop> propsFor(Object object) {
		assert object != null;
		List<Prop> props = new ArrayList<Prop>();
		Field[] fields = object.getClass().getFields();
		for (Field field : fields) {
			PropAnn p = field.getAnnotation(PropAnn.class);
			if (p != null) {
				Prop prop = null;
				PropPack pp = new PropPack(object, field);
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
				else if (ft == int.class) {
					prop = new IntegerProp(pp);
				}
				else if (ft == String.class) {
					prop = new StringProp(pp);
				}
				else {
					assert false : ft;
				}
				assert prop != null;
				props.add(0, prop);
			}
		}
		return props;
	}

	public static void copyProps(Object src, Object dest) {
		List<Prop> destProps = OPS.propsFor(dest);
		List<Prop> srcProps = OPS.propsFor(src);
		assert srcProps.size() == destProps.size();
		for (int x = 0; x < srcProps.size(); x++) {
			destProps.get(x).copyFrom(srcProps.get(x));
		}
	}

	public static void validate(Object object) {
		List<Prop> props = OPS.propsFor(object);
		for (Prop prop : props) {
			prop.validate();
		}
	}

	public static void saveProps(Object object, DataDestination dd) {
		List<Prop> props = OPS.propsFor(object);
		for (Prop prop : props) {
			dd.write(prop.label());
			prop.save(dd);
		}
	}

	public static void loadProps(Object object, DataItem di) {
		List<Prop> props = OPS.propsFor(object);
		for (Prop prop : props) {
			prop.load(di.requireField(prop.label()));
		}
	}
}
