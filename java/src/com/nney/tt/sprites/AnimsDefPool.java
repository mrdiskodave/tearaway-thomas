package com.nney.tt.sprites;

import com.nney.datanode.Node;
import com.nney.tt.resources.TTResource;

public class AnimsDefPool extends CachedLoader<String, Node> {
	@Override
	protected Node internalLoad(String k) {
		return TTResource.asNode(TTResource.spriteDef(k));
	}
}
