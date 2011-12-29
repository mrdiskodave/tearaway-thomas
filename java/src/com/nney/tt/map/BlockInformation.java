package com.nney.tt.map;

import java.util.HashMap;

import com.nney.datanode.Node;

/**
 * Some blocks are special. Some are ladder, some are stop-blocks, some are
 * slippery, some are magic. This class knows about this stuff.
 */
public class BlockInformation {
	private final HashMap<Integer, String> specs = new HashMap<Integer, String>(1, 0.1f);

	public BlockInformation(Node di) {
		Node[] z = di.requireList();
		int l = z.length;
		assert l % 1 == 0;
		for (int x = 0; x < l; x += 2) {
			String name = z[x].requireString();
			Node[] itemsDi = z[x + 1].requireList();
			for (Node itemDi : itemsDi) {
				int item = itemDi.requireInt();
				put(item, name);
			}
		}
	}

	public void put(int block, String name) {
		assert !specs.containsKey(block);
		specs.put(block, name);
	}

	public BlockInformation() {
	}

	public String get(int block) {
		return specs.get(block);
	}
}
