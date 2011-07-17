package com.nney.tt.sprites;

public class SpriteName {
	private String name;
	private int frame;

	public SpriteName(String key) {
		int z = key.indexOf('-');
		assert z >= 0;
		name = key.substring(0, z);
		frame = Integer.parseInt(key.substring(z + 1));
	}
	
	public SpriteName(String name, int frame) {
		this.name = name;
		this.frame = frame;
	}
	
	@Override
	public String toString() {
		return name+"-"+frame;
	}

	public String getName() {
		return name;
	}

	public int getFrame() {
		return frame;
	}
	
	@Override
	public boolean equals(Object obj) {
		SpriteName that = (SpriteName) obj;
		return that.name.equals(name) && that.frame==frame;
	}
	
	@Override
	public int hashCode() {
		return name.hashCode()+frame;
	}
}
