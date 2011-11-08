package com.nney.tt;

import com.nney.datanode.Node;
import com.nney.tt.input.JoystickTools;
import com.nney.tt.resources.TTResource;

public class ScriptReader {
	SimpleByteBuffer b = new SimpleByteBuffer();

	public ScriptReader(String content) {
		Node ns = TTResource.asNode(content);
		for (Node n : ns.requireList()) {
			byte j = JoystickTools.stringToJoystick(n.requireElement(0).requireString());
			int r = n.requireElement(1).requireInt();
			while (r-- > 0)
				b.add(j);
		}
		b.rewind();
	}

	int get() {
		return b.get();
	}
}
