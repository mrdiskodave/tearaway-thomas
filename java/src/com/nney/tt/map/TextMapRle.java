package com.nney.tt.map;

public class TextMapRle {
	public static String pack(short[] map, int offset, int length) {
		StringBuilder sb = new StringBuilder();
		int end = offset + length;
		while (offset < end) {
			int r = BinaryMapRle.countRun(map, offset, end);
			String o1 = String.format("%x,", map[offset]);
			String o2 = String.format("%x*%x,", r, map[offset]);
			int l1 = o1.length() * r;
			int l2 = o2.length();
			if (l1 <= l2) {
				for (int x = 0; x < r; x++) {
					sb.append(o1);
				}
			}
			else {
				sb.append(o2);
			}
			offset += r;
		}
		sb.deleteCharAt(sb.length() - 1);
		return sb.toString();
	}

	public static void unpack(short[] map, int offset, int length, String content) {
		int limit = offset + length;
		int p = 0;
		while (p < content.length()) {
			int r = 1;
			int v = 0;
			while (p < content.length()) {
				int c = content.charAt(p++);
				int z = "0123456789abcdef,*".indexOf(c);
				if (z < 0)
					throw new RuntimeException("Bad character in text packed map");
				else if (z == 16)
					break;
				else if (z == 17) {
					r = v;
					v = 0;
				}
				else {
					v <<= 4;
					v += z;
				}
			}
			if (offset + r > limit) throw new RuntimeException("Text packed map too big");
			for (int x = 0; x < r; x++) {
				map[offset++] = (short) v;
			}
		}
		if (offset < limit)
			throw new RuntimeException("Text packed map too small - it finished on " + offset + " not " + limit);
	}

	public static String pack(short[] s) {
		return pack(s, 0, s.length);
	}
}
