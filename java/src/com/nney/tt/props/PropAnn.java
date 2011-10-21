package com.nney.tt.props;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface PropAnn {
	String name();

	String doc() default "";;

	String xtraDef() default "";
	
	String label();
}


