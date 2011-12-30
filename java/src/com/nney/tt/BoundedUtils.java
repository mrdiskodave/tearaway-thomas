package com.nney.tt;

import java.util.List;

import com.nney.tt.geom.Box;

public class BoundedUtils {
	public static <T extends Bounded> Box collect(List<T> hbs) {
		Box answer = null;
		for (Bounded hb : hbs) {
			Box b = hb.getBounds();
			if (answer == null) {
				answer = b.copy();
			}
			else {
				answer.accommodate(b);
			}
		}
		return answer;
	}
}
