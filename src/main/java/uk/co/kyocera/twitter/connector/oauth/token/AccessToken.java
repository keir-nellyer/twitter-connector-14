package uk.co.kyocera.twitter.connector.oauth.token;

public class AccessToken extends Token {
    private final long userId;
    private final String screenName;

    public AccessToken(String token, String secret, long userId, String screenName) {
        super(token, secret);
        this.userId = userId;
        this.screenName = screenName;
    }

    public long getUserId() {
        return userId;
    }

    public String getScreenName() {
        return screenName;
    }
}
