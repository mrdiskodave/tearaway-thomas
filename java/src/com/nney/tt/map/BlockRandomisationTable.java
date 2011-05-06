package com.nney.tt.map;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

import com.nney.json.DataItem;

public class BlockRandomisationTable {
	private final HashMap<Integer, ArrayList<Integer>> expand = new HashMap<Integer, ArrayList<Integer>>(1, 0.1f);
	private final HashMap<Integer, Integer> compress = new HashMap<Integer, Integer>(1, 0.1f);
	
	private final Random r = new Random();
	
	public BlockRandomisationTable(DataItem di) {
		for (DataItem line: di.requireList()) {
			ArrayList<Integer> al = new ArrayList<Integer>();
			for (DataItem x: line.requireList()) {
				al.add(x.requireInt());
			}
			registerLine(al);
		}
	}

	private void registerLine(ArrayList<Integer> al) {
		for (int x=0; x<al.size(); x++) {
			registerExpansion(al.get(x), al);
			if (x!=0) {
				registerCompression(al.get(x), al.get(0));
			}
		}
	}

	private void registerCompression(Integer src, Integer dest) {
		assert !compress.containsKey(src);
		compress.put(src, dest);
	}

	private void registerExpansion(Integer src, ArrayList<Integer> dest) {
		assert !expand.containsKey(src);
		expand.put(src, dest);
	}

	public int shuffle(int block) {
		if (!expand.containsKey(block)) return block;

		ArrayList<Integer> a = expand.get(block);
		return a.get(r.nextInt(a.size()));
	}
	
	public int compress(int block) {
		Integer block2 = compress.get(block);
		if (block2==null) return block;
		return block2;
	}
}
