package dev.kaidev.common.validation;

import java.lang.annotation.*;
import jakarta.validation.*;
import jakarta.validation.constraints.*;

@Documented
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {})
@NotBlank(message = "Email is required")
@Email(message = "Email must be a valid email address")
@Size(max = 254, message = "Email must contain at most 254 characters")
public @interface ValidEmail {
    String message() default "Email is invalid";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
