package uk.co.kyocera.twitter.connector.oauth;

public class OAuthConfig {
    private final String key;
    private final String secret;
    private final String callbackURL;

    public OAuthConfig(String key, String secret, String callbackURL) {
        this.key = key;
        this.secret = secret;
        this.callbackURL = callbackURL;
    }

    public String getKey() {
        return key;
    }

    public String getSecret() {
        return secret;
    }

    public String getCallbackURL() {
        return callbackURL;
    }
}
