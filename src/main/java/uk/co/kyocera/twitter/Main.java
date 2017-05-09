package uk.co.kyocera.twitter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import uk.co.kyocera.twitter.connector.Twitter;
import uk.co.kyocera.twitter.connector.exception.TokenException;
import uk.co.kyocera.twitter.connector.exception.TwitterException;
import uk.co.kyocera.twitter.connector.oauth.OAuthConfig;

import java.io.*;
import java.net.URL;
import java.security.Security;

public class Main {
    private static final String CONSUMER_KEY = "R3zGaVVKuW6uQZy6YxaT9bzRM";
    private static final String CONSUMER_SECRET = "jVXVR2gmG3Eycrbj6t1Sbcq2jEbOkdDh1NzbXTfKIsDu0KIDYd";
    public static final String AUTHORIZE_CALLBACK_URL = "http://127.0.0.1:8080/process_callback";

    public static void main(String[] args) throws IOException, TwitterException, TokenException { // TODO do proper error handling
        // Java 1.4 cannot seem to handle a seemingly simple SSL connection to Twitter
        // By utilising the BouncyCastle library, we can add it as a SecurityProvider and it'll handle this for us
        Security.addProvider(new BouncyCastleProvider());

        OAuthConfig oauthConfig = new OAuthConfig(CONSUMER_KEY, CONSUMER_SECRET);
        Twitter twitter = new Twitter("Kyocera SocialLink", oauthConfig);

        if (twitter.fetchRequestToken(AUTHORIZE_CALLBACK_URL)) {
            URL authenticateURL = twitter.getAuthenticateURL("scan_to_social");
            System.out.println("Authenticate URL: " + authenticateURL.toString());

            System.out.println("Paste oauth_verifier string");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            if (twitter.fetchAccessToken(reader.readLine())) {
                long mediaId = twitter.uploadMedia(new File("java-logo.jpg"));

                if (mediaId != -1) {
                    long statusId = twitter.updateStatus("Test from pure Java 1.4 environment", new long[]{mediaId});

                    if (statusId != -1) {
                        System.out.println("Status updated, id = " + statusId);
                    } else {
                        System.out.println("Error whilst updating status.");
                    }
                } else {
                    System.out.println("Error whilst uploading media.");
                }
            } else {
                System.out.println("Error whilst receiving access token.");
            }
        } else {
            System.out.println("Error whilst receiving request token.");
        }
    }
}
