package uk.co.kyocera.twitter.connector.oauth;

public class Token {
    protected final String token;
    protected final String secret;

    public Token(String token, String secret) {
        this.token = token;
        this.secret = secret;
    }

    public String getToken() {
        return token;
    }

    public String getSecret() {
        return secret;
    }
}
