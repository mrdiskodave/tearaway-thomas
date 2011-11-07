package com.nney.tt.sprites;

import java.io.IOException;

import com.nney.datanode.Node;
import com.nney.json.JsonException;
import com.nney.json.JsonParser;
import com.nney.tt.resources.TTResource;
import com.nney.utils.StringIO;

public class AnimsDefPool extends CachedLoader<String, Node> {
	@Override
	protected Node internalLoad(String k) {
		try {
			String text = StringIO.loadText(TTResource.spriteDef(k), null);
			return JsonParser.parse(text);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}

}
