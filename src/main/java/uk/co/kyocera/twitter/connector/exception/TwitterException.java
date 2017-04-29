package uk.co.kyocera.twitter.connector.exception;

public class TwitterException extends Exception {
    public TwitterException() {
    }

    public TwitterException(String message) {
        super(message);
    }

    public TwitterException(String message, Throwable cause) {
        super(message, cause);
    }

    public TwitterException(Throwable cause) {
        super(cause);
    }
}
