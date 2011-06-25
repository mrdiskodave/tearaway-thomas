package com.nney.tt.aliens;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface AlienInfoAnn {
	int type();

	String gfx();
	
	int score() default 0;
}
