package com.nney.tt.map;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

import com.nney.json.DataItem;

public class BlockAliasTable {
	private final HashMap<Integer, ArrayList<Integer>> expand = new HashMap<Integer, ArrayList<Integer>>(1, 0.1f);
	private final HashMap<Integer, Integer> compress = new HashMap<Integer, Integer>(1, 0.1f);

	private final Random r = new Random();

	public BlockAliasTable(DataItem di) {
		for (DataItem line : di.requireList()) {
			ArrayList<Integer> al = new ArrayList<Integer>();
			for (DataItem x : line.requireList()) {
				al.add(x.requireInt());
			}
			registerLine(al);
		}
	}

	/**
	 * The whole line is full of aliases for the same block. The first entry is
	 * the canonical representation for the block.
	 * 
	 * @param al
	 *            A line of block numbers.
	 */
	private void registerLine(ArrayList<Integer> al) {
		for (int x = 0; x < al.size(); x++) {
			registerExpansion(al.get(x), al);
			if (x != 0) {
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

	/**
	 * Randomly shuffle the given block number - producing the same block number
	 * or one of its aliases (if it has any) all with equal probability.
	 * 
	 * @param block
	 *            A block number.
	 * @return A block number.
	 */
	public int shuffle(int block) {
		ArrayList<Integer> row = expand.get(block);
		if (row == null) return block;
		int answer = row.get(r.nextInt(row.size()));
		// System.out.println(block+"-shuffle->"+answer);
		return answer;
	}

	/**
	 * Compress the given block number reducing it to its canonical
	 * representation.
	 * 
	 * @param block
	 *            Any block number.
	 * @return A canonical block number.
	 */
	public int compress(int block) {
		Integer answer = compress.get(block);
		if (answer == null) return block;
		// System.out.println(block+"-compress->"+answer);
		return answer;
	}
}
