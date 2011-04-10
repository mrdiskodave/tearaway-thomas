package com.nney.tt.aliens;

import com.nney.json.DataItem;
import com.nney.tt.geom.Box;

public class DataItemHelpers {
	static public Box loadBox(DataItem diBox) {
		int l = diBox.requireElement(0).requireInt();
		int t = diBox.requireElement(1).requireInt();
		int r = diBox.requireElement(2).requireInt();
		int b = diBox.requireElement(3).requireInt();
		Box answer = new Box(l, t, r, b);
		return answer;
	}
}
