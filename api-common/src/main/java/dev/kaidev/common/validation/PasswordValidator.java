package dev.kaidev.common.validation;

import java.nio.charset.StandardCharsets;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value != null && !value.isBlank() && value.codePointCount(0, value.length()) >= 12
                && value.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
