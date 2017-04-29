package uk.co.kyocera.twitter.connector.oauth;

public class RequestToken {
    private final String token;
    private final String tokenSecret;

    public RequestToken(String token, String tokenSecret) {
        this.token = token;
        this.tokenSecret = tokenSecret;
    }

    public String getToken() {
        return token;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }
}
