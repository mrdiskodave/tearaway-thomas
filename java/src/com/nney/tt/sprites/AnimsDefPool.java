package com.nney.tt.sprites;

import com.nney.datanode.Node;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Openable;

public class AnimsDefPool extends CachedLoader<String, Node> {
	@Override
	protected Node internalLoad(String k) {
		Openable o = TTResource.animDef(k);
		if (o == null) return null;
		return TTResource.asNode(o);
	}
}
