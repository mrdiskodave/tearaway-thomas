package com.nney.tt.aliens;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface AlienProp {
	String name();

	String doc() default "";;

	String xtraDef() default "";
	
	String label();
}


