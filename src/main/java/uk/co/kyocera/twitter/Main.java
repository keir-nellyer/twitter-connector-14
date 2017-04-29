package uk.co.kyocera.twitter;

import uk.co.kyocera.twitter.connector.Twitter;
import uk.co.kyocera.twitter.connector.oauth.OAuthConfig;

import java.io.IOException;

public class Main {
    private static final String CONSUMER_KEY = "R3zGaVVKuW6uQZy6YxaT9bzRM";
    private static final String CONSUMER_SECRET = "jVXVR2gmG3Eycrbj6t1Sbcq2jEbOkdDh1NzbXTfKIsDu0KIDYd";

    public static void main(String[] args) throws IOException {
        Twitter twitter = new Twitter(new OAuthConfig(CONSUMER_KEY, CONSUMER_SECRET));

        twitter.requestBearerToken("https://api.twitter.com/oauth2/token");
        String tweet = twitter.fetchTimelineTweet("https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=twitterapi&count=2");
        System.out.println(tweet);
    }
}
