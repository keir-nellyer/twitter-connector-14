package uk.co.kyocera.twitter;

import twitter4j.*;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;
import twitter4j.conf.Configuration;
import twitter4j.conf.ConfigurationBuilder;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;

public class Main {
    private static final String CONSUMER_KEY = "R3zGaVVKuW6uQZy6YxaT9bzRM";
    private static final String CONSUMER_SECRET = "jVXVR2gmG3Eycrbj6t1Sbcq2jEbOkdDh1NzbXTfKIsDu0KIDYd";

    public static void main(String[] args) {
        Configuration config = new ConfigurationBuilder()
                .setOAuthConsumerKey(CONSUMER_KEY)
                .setOAuthConsumerSecret(CONSUMER_SECRET)
                .setUseSSL(true) // this MUST be true
                .setRestBaseURL("https://api.twitter.com/1.1/")
                .build();

        //fixUploadURL(config);

        Twitter twitter = new TwitterFactory(config).getInstance();

        try {
            RequestToken requestToken = getRequestToken(twitter);

            if (requestToken != null) {
                boolean gotAccessToken = fetchAccessToken(twitter, requestToken);

                if (gotAccessToken) {
                    File imageFile = new File("src/main/resources/image.jpg");

                    StatusUpdate statusUpdate =
                            new StatusUpdate("Test Image from Java Application (" + System.currentTimeMillis() + ")")
                                    .media(imageFile);

                    try {
                        Status status = twitter.updateStatus(statusUpdate);
                        System.out.println("Posted tweet: " + status.getText());
                    } catch (TwitterException e) {
                        System.out.println("Unable to reach Twitter service.");
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean fixUploadURL(Configuration config) {
        try {
            // class is package-private, must find manually
            Class configClass = Class.forName("twitter4j.conf.ConfigurationBase");
            Field uploadBaseUrlField = configClass.getDeclaredField("uploadBaseURL");
            uploadBaseUrlField.setAccessible(true);
            uploadBaseUrlField.set(config, "https://upload.twitter.com/1.1/");
            return true;
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        return false;
    }

    private static boolean fetchAccessToken(Twitter twitter, RequestToken requestToken) throws IOException {
        AccessToken accessToken = null;
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        while (accessToken == null) {
            System.out.println("Open the following URL and grant access to your account:");
            System.out.println(requestToken.getAuthorizationURL());
            System.out.println("Enter the PIN if available, otherwise just press enter.");
            System.out.print("[PIN]: ");

            String pin = reader.readLine();

            try {
                if (pin.length() > 0) {
                    accessToken = twitter.getOAuthAccessToken(requestToken, pin);
                } else {
                    accessToken = twitter.getOAuthAccessToken(requestToken);
                }

                System.out.println("Got access token");
                System.out.println("Access token: " + accessToken.getToken());
                System.out.println("Access token secret: " + accessToken.getTokenSecret());
            } catch (TwitterException e) {
                if (e.getStatusCode() == 401) {
                    System.out.println("Unable to get access token.");
                }

                e.printStackTrace();
            } catch (IllegalStateException e) {
                if (twitter.getAuthorization().isEnabled()) {
                    e.printStackTrace();
                } else {
                    System.out.println("OAuth consumer key/secret not set.");
                }

                break;
            }
        }

        return accessToken != null;
    }

    private static RequestToken getRequestToken(Twitter twitter) {
        RequestToken requestToken = null;

        try {
            requestToken = twitter.getOAuthRequestToken();
            System.out.println("Got request token");
            System.out.println("Request token: " + requestToken.getToken());
            System.out.println("Request token secret: " + requestToken.getTokenSecret());
        } catch (TwitterException e) {
            System.out.println("Unable to reach Twitter service.");
            e.printStackTrace();
        }

        return requestToken;
    }
}
