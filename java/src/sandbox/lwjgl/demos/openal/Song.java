package sandbox.lwjgl.demos.openal;

public class Song {
	private DataSrc dataSrc;
	private DataSrc info;

	public Song(DataSrc d) {
		assert d.g4cc(0).equals("DSNG");
		dataSrc = d.dsx(4, d.length()-4);
		info = findBlock("INFO");
	}
	
	byte[] getSequence() {
		return findBlock("SEQU").xx(0, info.uw(0));
	}
	
	int clickLength() {
		return info.uw(4);
	}

	byte[] block(int x) {
		DataSrc b = findBlock("BLK"+((char)x));
		return b.xx(2, b.length()-2);
	}
	
	DataSrc findBlock(String name) {
		int p = 0;
		for (;;) {
			if (dataSrc.ul(p)==0 || p>=dataSrc.length()) {
				return null;
			}
			String blockName = dataSrc.g4cc(p);
			p += 4;
			int l = dataSrc.ul(p);
			p += 4;
			if (name.equals(blockName)) {
//				System.out.println(String.format("Found %s and %s it has length %s", name, p, l));
				return dataSrc.dsx(p, l);
			}
			p += l;
		}
	}
}
