package dev.kaidev.common.validation.annotation;

import dev.kaidev.common.validation.validator.PasswordValidator;

import java.lang.annotation.*;
import jakarta.validation.*;

@Documented
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordValidator.class)
public @interface ValidPassword {
    int min() default 12;
    String message() default "Password must contain at least 12 characters and at most 72 UTF-8 bytes";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
