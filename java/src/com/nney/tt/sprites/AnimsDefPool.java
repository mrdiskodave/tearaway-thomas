package com.nney.tt.sprites;

import java.io.IOException;

import com.nney.json.DataItem;
import com.nney.json.JsonException;
import com.nney.json.JsonValue;
import com.nney.tt.resources.TTResource;
import com.nney.utils.StringIO;

public class AnimsDefPool extends CachedLoader<String, DataItem> {
	@Override
	protected DataItem populatePool(String k) {
		try {
			String text = StringIO.loadText(TTResource.spriteDef(k), null);
			return JsonValue.parse(text);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}
	
}
