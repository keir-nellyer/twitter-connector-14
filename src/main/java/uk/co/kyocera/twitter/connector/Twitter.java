package uk.co.kyocera.twitter.connector;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import uk.co.kyocera.twitter.connector.exception.TwitterException;
import uk.co.kyocera.twitter.connector.oauth.OAuthConfig;
import uk.co.kyocera.twitter.connector.oauth.RequestToken;
import uk.co.kyocera.twitter.connector.util.Util;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class Twitter {
    private static final String REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token";

    private final String userAgent;
    private final OAuthConfig oauthConfig;

    private RequestToken requestToken = null;

    public Twitter(String userAgent, OAuthConfig oauthConfig) {
        this.userAgent = userAgent;
        this.oauthConfig = oauthConfig;
    }

    public boolean fetchRequestToken() throws TwitterException {
        Map authHeader = getDefaultOAuthHeader();
        authHeader.put("oauth_callback", "http://127.0.0.1:8080/process_callback");
        authHeader.put("oauth_signature", getSignature("POST", REQUEST_TOKEN_URL, authHeader));

        HttpsURLConnection connection = null;

        try {
            URL url = new URL(REQUEST_TOKEN_URL);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Host", "api.twitter.com");
            connection.setRequestProperty("User-Agent", userAgent);
            connection.setRequestProperty("Authorization", "OAuth " + getHeader(authHeader));
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
            connection.setUseCaches(false);

            writeRequest(connection, "");
            String responseBody = readResponse(connection);

            if (connection.getResponseCode() >= 400) {
                JSONObject jsonObject = (JSONObject) JSONValue.parse(responseBody);

                if (jsonObject.containsKey("errors")) {
                    JSONArray errors = (JSONArray) jsonObject.get("errors");
                    throw new TwitterException(errors.toString());
                } else {
                    throw new TwitterException("Twitter API returned response code: " + connection.getResponseCode());
                }
            } else {
                Map response = parseEncodedResponse(responseBody);
                String token = (String) response.get("oauth_token");
                String secret = (String) response.get("oauth_token_secret");
                requestToken = new RequestToken(token, secret);
                return true;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return false;
    }

    private Map getDefaultOAuthHeader() {
        Map authHeader = new HashMap();
        long timeMillis = System.currentTimeMillis();
        long timeSecs = timeMillis / 1000;
        authHeader.put("oauth_nonce", String.valueOf(timeMillis)); // use time millis for ease
        authHeader.put("oauth_signature_method", "HMAC-SHA1");
        authHeader.put("oauth_timestamp", String.valueOf(timeSecs));
        authHeader.put("oauth_consumer_key", oauthConfig.getKey());
        authHeader.put("oauth_version", "1.0");
        return authHeader;
    }

    private Map parseEncodedResponse(String responseBody) {
        Map response = new HashMap();
        StringTokenizer tokenizer = new StringTokenizer(responseBody, "&");

        while (tokenizer.hasMoreTokens()) {
            String currentToken = tokenizer.nextToken();
            int separatorIndex = currentToken.indexOf('=');

            if (separatorIndex != -1) {
                String key = currentToken.substring(0, separatorIndex);
                String value = currentToken.substring(separatorIndex + 1);
                response.put(key, value);
            }
        }

        return response;
    }

    private String getHeader(Map parameters) {
        StringBuffer buffer = new StringBuffer();
        Iterator iterator = parameters.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();

            buffer.append(Util.percentEncode(key));
            buffer.append("=\"");
            buffer.append(Util.percentEncode(value));
            buffer.append("\"");

            if (iterator.hasNext()) {
                buffer.append(", ");
            }
        }

        return buffer.toString();
    }

    private String getEncodedParameterString(Map parameters) {
        StringBuffer buffer = new StringBuffer();
        Iterator iterator = parameters.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();

            buffer.append(Util.percentEncode(key));
            buffer.append("=");
            buffer.append(Util.percentEncode(value));

            if (iterator.hasNext()) {
                buffer.append("&");
            }
        }

        return buffer.toString();
    }

    private String getSignature(String method, String baseURL, Map parameters) {
        // sort parameters by values and keys so they are in the correct order for signing
        parameters = Util.sortByValue(parameters);
        parameters = Util.sortByKey(parameters);

        String encodedParameterString = getEncodedParameterString(parameters);
        String baseAuthSignature = getBaseAuthSignature(method, baseURL, encodedParameterString);
        return Util.hmacSha1(getSigningKey(), baseAuthSignature);
    }

    private String getBaseAuthSignature(String method, String baseURL, String paramString) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(method.toUpperCase());
        buffer.append("&");
        buffer.append(Util.percentEncode(baseURL));
        buffer.append("&");
        buffer.append(Util.percentEncode(paramString));
        return buffer.toString();
    }

    private String getSigningKey() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(Util.percentEncode(oauthConfig.getSecret()));
        buffer.append("&");

        if (requestToken != null) {
            buffer.append(Util.percentEncode(requestToken.getSecret()));
        }

        return buffer.toString();
    }

    private static boolean writeRequest(HttpsURLConnection connection, String textBody) {
        try {
            BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
            wr.write(textBody);
            wr.flush();
            wr.close();

            return true;
        }
        catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String readResponse(HttpsURLConnection connection) {
        try {
            StringBuffer str = new StringBuffer();
            InputStream inputStream;

            if (connection.getResponseCode() >= 400) {
                inputStream = connection.getErrorStream();
            } else {
                inputStream = connection.getInputStream();
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
            String line;

            while((line = br.readLine()) != null) {
                str.append(line).append(System.getProperty("line.separator"));
            }

            return str.toString();
        }
        catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }
}
