package com.nney.tt.props;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface PropAnn {
	String name() default "";

	String doc();

	String xtraDef() default "";

	String label() default "";

	int min() default 0;

	int max() default Integer.MAX_VALUE;
}
