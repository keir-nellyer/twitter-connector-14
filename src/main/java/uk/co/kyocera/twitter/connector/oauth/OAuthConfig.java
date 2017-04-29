package uk.co.kyocera.twitter.connector.oauth;

public class OAuthConfig {
    private final String key;
    private final String secret;

    public OAuthConfig(String key, String secret) {
        this.key = key;
        this.secret = secret;
    }

    public String getKey() {
        return key;
    }

    public String getSecret() {
        return secret;
    }
}
