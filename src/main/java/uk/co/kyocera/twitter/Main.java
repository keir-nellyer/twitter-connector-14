package uk.co.kyocera.twitter;

import uk.co.kyocera.twitter.connector.Twitter;
import uk.co.kyocera.twitter.connector.exception.TwitterException;
import uk.co.kyocera.twitter.connector.oauth.OAuthConfig;

import java.io.IOException;
import java.net.URL;

public class Main {
    private static final String CONSUMER_KEY = "R3zGaVVKuW6uQZy6YxaT9bzRM";
    private static final String CONSUMER_SECRET = "jVXVR2gmG3Eycrbj6t1Sbcq2jEbOkdDh1NzbXTfKIsDu0KIDYd";

    public static void main(String[] args) throws IOException {
        Twitter twitter = new Twitter("Kyocera SocialLink", new OAuthConfig(CONSUMER_KEY, CONSUMER_SECRET));

        try {
            twitter.fetchRequestToken();
        } catch (TwitterException e) {
            e.printStackTrace();
        }

        URL authenticateURL = twitter.getAuthenticateURL();
        System.out.println("Authenticate URL: " + authenticateURL.toString());
    }
}
