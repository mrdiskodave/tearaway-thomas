package com.nney.tt.sounds.music;

public class Song {
	private DataSrc dataSrc;
	private DataSrc info;

	public Song(DataSrc d) {
		if (!d.fourCharacterCode(0).equals("DSNG")) {
			throw new RuntimeException("Doesn't look a song file to me");
		}
		dataSrc = d.subDataSrc(4, d.length()-4);
		info = findBlock("INFO");
	}
	
	byte[] getSequence() {
		return findBlock("SEQU").rawData(0, info.unsignedWordBE(0));
	}
	
	int clickLength() {
		// it's stored in DBF form!
		return info.unsignedWordBE(4) + 1;
	}

	byte[] block(int x) {
		DataSrc b = findBlock("BLK"+((char)x));
		return b.rawData(2, b.length()-2);
	}
	
	DataSrc findBlock(String name) {
		int p = 0;
		for (;;) {
			if (dataSrc.unsignedLongBE(p)==0 || p>=dataSrc.length()) {
				return null;
			}
			String blockName = dataSrc.fourCharacterCode(p);
			p += 4;
			int l = dataSrc.unsignedLongBE(p);
			p += 4;
			if (name.equals(blockName)) {
//				System.out.println(String.format("Found %s and %s it has length %s", name, p, l));
				return dataSrc.subDataSrc(p, l);
			}
			p += l;
		}
	}
}
