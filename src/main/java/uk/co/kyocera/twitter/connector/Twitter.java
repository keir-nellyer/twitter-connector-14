package uk.co.kyocera.twitter.connector;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.PostMethod;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import uk.co.kyocera.twitter.connector.oauth.OAuthConfig;
import uk.co.kyocera.twitter.connector.oauth.RequestToken;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class Twitter {
    private static final String HMAC_SHA1 = "HmacSHA1";

    private final HttpClient httpClient = new HttpClient();

    private final OAuthConfig oauthConfig;

    private String bearerToken = null;

    public Twitter(OAuthConfig oauthConfig) {
        this.oauthConfig = oauthConfig;
    }

    // Encodes the consumer key and secret to create the basic authorization key
    private static String encodeKeys(String consumerKey, String consumerSecret) {
        try {
            String encodedConsumerKey = URLEncoder.encode(consumerKey, "UTF-8");
            String encodedConsumerSecret = URLEncoder.encode(consumerSecret, "UTF-8");

            String fullKey = encodedConsumerKey + ":" + encodedConsumerSecret;
            byte[] encodedBytes = Base64.encodeBase64(fullKey.getBytes());
            return new String(encodedBytes);
        }
        catch (UnsupportedEncodingException e) {
            return new String();
        }
    }

    // Constructs the request for requesting a bearer token and returns that token as a string
    public void requestBearerToken(String endPointUrl) throws IOException {
        HttpsURLConnection connection = null;
        String encodedCredentials = encodeKeys(oauthConfig.getKey(),oauthConfig.getSecret());

        try {
            URL url = new URL(endPointUrl);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Host", "api.twitter.com");
            connection.setRequestProperty("User-Agent", "Your Program Name");
            connection.setRequestProperty("Authorization", "Basic " + encodedCredentials);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
            connection.setRequestProperty("Content-Length", "29");
            connection.setUseCaches(false);

            writeRequest(connection, "grant_type=client_credentials");

            // Parse the JSON response into a JSON mapped object to fetch fields from.
            JSONObject obj = (JSONObject)JSONValue.parse(readResponse(connection));

            if (obj != null) {
                String tokenType = (String)obj.get("token_type");
                String token = (String)obj.get("access_token");

                bearerToken = ((tokenType.equals("bearer")) && (token != null)) ? token : "";
            } else {
                bearerToken = "";
            }
        }
        catch (MalformedURLException e) {
            throw new IOException("Invalid endpoint URL specified."/*, e*/);
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    // Fetches the first tweet from a given user's timeline
    public String fetchTimelineTweet(String endPointUrl) throws IOException {
        HttpsURLConnection connection = null;

        try {
            URL url = new URL(endPointUrl);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Host", "api.twitter.com");
            connection.setRequestProperty("User-Agent", "Your Program Name");
            connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
            connection.setUseCaches(false);


            // Parse the JSON response into a JSON mapped object to fetch fields from.
            JSONArray obj = (JSONArray)JSONValue.parse(readResponse(connection));

            if (obj != null) {
                String tweet = ((JSONObject)obj.get(0)).get("text").toString();

                return (tweet != null) ? tweet : "";
            }
            return new String();
        }
        catch (MalformedURLException e) {
            throw new IOException("Invalid endpoint URL specified."/*, e*/);
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    // Writes a request to a connection
    private static boolean writeRequest(HttpsURLConnection connection, String textBody) {
        try {
            BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
            wr.write(textBody);
            wr.flush();
            wr.close();

            return true;
        }
        catch (IOException e) { return false; }
    }


    // Reads a response for a given connection and returns it as a string.
    private static String readResponse(HttpsURLConnection connection) {
        try {
            StringBuffer str = new StringBuffer();

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line = "";
            while((line = br.readLine()) != null) {
                str.append(line + System.getProperty("line.separator"));
            }
            return str.toString();
        }
        catch (IOException e) { return new String(); }
    }
}
