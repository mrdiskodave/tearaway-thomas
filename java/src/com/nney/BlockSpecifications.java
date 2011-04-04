package com.nney;

import java.util.HashMap;

import com.nney.json.DataException;
import com.nney.json.DataItem;

public class BlockSpecifications {
	private final HashMap<Integer, String> specs = new HashMap<Integer, String>(1, 0.1f); 

	public BlockSpecifications(DataItem di) throws DataException {
		DataItem[] z = di.requireList();
		int l = z.length;
		assert l%1 == 0;
		for (int x=0; x<l; x+=2 ) {
			String name = z[x].requireString();
			DataItem[] itemsDi = z[x+1].requireList();
			for (DataItem itemDi: itemsDi) {
				int item = itemDi.requireInt();
				assert !specs.containsKey(item);
				specs.put(item, name);
			}
		}
	}
	
	public String get(int block) {
		return specs.get(block);
	}
}
