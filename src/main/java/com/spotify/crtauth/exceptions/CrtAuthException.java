package com.spotify.crtauth.exceptions;

public class CrtAuthException extends Exception {
  public CrtAuthException() {
    super();
  }

  public CrtAuthException(String message) {
    super(message);
  }

  public CrtAuthException(Throwable throwable) {
    super(throwable);
  }

  public CrtAuthException(String message, Throwable cause) {
    super(message, cause);
  }
}