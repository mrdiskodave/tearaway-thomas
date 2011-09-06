package com.nney.tt.sounds.music;

public class ChannelConfig {
	public final float position;
	public final boolean enabled;

	ChannelConfig(float d, boolean enabled) {
		this.position = d;
		this.enabled = enabled;
	}

	public boolean onTheLeft() {
		return position<0.5f;
	}
}
