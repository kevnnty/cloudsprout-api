package com.cloudsprout.drive.api.payload;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
  private boolean success;
  private String message;
  private HttpStatus status;
  private T payload;
  private Object error;
  private final String timestamp = LocalDateTime.now().toString();

  // Success Response
  public static <T> ResponseEntity<ApiResponse<T>> success(String message, HttpStatus status, T payload) {
    return ResponseEntity.status(status).body(
        ApiResponse.<T>builder()
            .success(true)
            .message(message)
            .status(status)
            .payload(payload)
            .build());
  }

  // Error Response
  public static ResponseEntity<ApiResponse<Object>> error(String message, HttpStatus status, Object errorDetails) {
    return ResponseEntity.status(status).body(
        ApiResponse.builder()
            .success(false)
            .message(message)
            .status(status)
            .error(errorDetails)
            .build());
  }
}
