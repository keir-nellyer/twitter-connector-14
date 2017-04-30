package uk.co.kyocera.twitter.connector.oauth;

public class AccessToken {
    private final String token;
    private final String secret;
    private final long userId;
    private final String screenName;

    public AccessToken(String token, String secret, long userId, String screenName) {
        this.token = token;
        this.secret = secret;
        this.userId = userId;
        this.screenName = screenName;
    }

    public String getToken() {
        return token;
    }

    public String getSecret() {
        return secret;
    }

    public long getUserId() {
        return userId;
    }

    public String getScreenName() {
        return screenName;
    }
}
