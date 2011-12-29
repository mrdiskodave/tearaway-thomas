package com.nney.tt;

import com.nney.datanode.DataDestination;
import com.nney.json.IndentedJsonFormatter;
import com.nney.json.JsonDataDestination;
import com.nney.json.SafeWriter;
import com.nney.json.StringSafeWriter;
import com.nney.tt.input.JoystickTools;

public class ScriptWriter {
	SimpleByteBuffer b = new SimpleByteBuffer();

	void put(int x) {
		b.add((byte) x);
	}

	String save() {
		byte[] data = b.toByteArray();

		SafeWriter sw = new StringSafeWriter();
		IndentedJsonFormatter ijf = new IndentedJsonFormatter(sw);
		ijf.spaciousSeperators();
		DataDestination dd = new JsonDataDestination(ijf);
		dd.beginArray();

		int p = 0;
		while (p < data.length) {
			byte c = data[p];
			int r = 1;
			while (p + r < data.length && data[p + r] == c) {
				r++;
			}
			dd.beginArray();
			dd.write(JoystickTools.joystickToString(c));
			dd.write(r);
			dd.end();

			p += r;
		}

		dd.end();
		return sw.toString();
	}
}
