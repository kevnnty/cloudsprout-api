package com.cloudsprout.drive.api.exceptions;

import lombok.Getter;

@Getter
public class CustomException extends Exception {
    public CustomException(String message) {
        super(message);
    }
}
