package com.nney.tt.mapper;

import com.nney.tt.mapper.Mapper.Tool;

class ToolSlot {
	private Tool tool;

	Tool get() {
		return tool;
	}

	void change(Tool mm) {
		stop();
		tool = mm;
		start();
	}

	private void start() {
		if (tool != null) {
			tool.start();
		}
	}

	private void stop() {
		if (tool != null) {
			tool.stop();
		}
	}
}
