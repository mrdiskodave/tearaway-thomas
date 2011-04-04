package com.nney;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

import com.nney.json.DataException;
import com.nney.json.DataItem;

public class BlockRandomisationTable {
	private final HashMap<Integer, ArrayList<Integer>> tm = new HashMap<Integer, ArrayList<Integer>>(1, 0.1f);
	
	private final Random r = new Random();
	
	public BlockRandomisationTable(DataItem di) throws DataException {
		for (DataItem line: di.requireList()) {
			ArrayList<Integer> al = new ArrayList<Integer>();
			for (DataItem x: line.requireList()) {
				al.add(x.requireInt());
			}
			for (int x: al) {
				registerTransformation(x, al);
			}
		}
	}

	public void registerTransformation(int block, ArrayList<Integer> becomes) {
		assert !tm.containsKey(block);
		tm.put(block, becomes);
	}

	public int shuffle(int block) {
		if (!tm.containsKey(block)) return block;

		ArrayList<Integer> a = tm.get(block);
		return a.get(r.nextInt(a.size()));
	}

}
