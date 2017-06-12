package uk.co.kyocera.twitter.connector;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import uk.co.kyocera.twitter.connector.exception.TokenException;
import uk.co.kyocera.twitter.connector.exception.TwitterException;
import uk.co.kyocera.twitter.connector.oauth.*;
import uk.co.kyocera.twitter.connector.oauth.token.AccessToken;
import uk.co.kyocera.twitter.connector.oauth.token.RequestToken;
import uk.co.kyocera.twitter.connector.oauth.token.Token;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Twitter {
    private static final String REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token";
    private static final String AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize";
    private static final String ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token";
    private static final String MEDIA_UPLOAD_URL = "https://upload.twitter.com/1.1/media/upload.json";
    private static final String UPDATE_STATUS_URL = "https://api.twitter.com/1.1/statuses/update.json";

    private final String userAgent;
    private final OAuthConfig oauthConfig;

    private final HttpClient httpClient = new HttpClient();
    private Token token = null;

    public Twitter(String userAgent, OAuthConfig oauthConfig) {
        this.userAgent = userAgent;
        this.oauthConfig = oauthConfig;
    }

    public boolean fetchRequestToken(String callbackURL) throws TwitterException, TokenException {
        if (token != null) {
            throw new TokenException("Token already present.");
        }

        OAuthHeader authHeader = new OAuthHeader(oauthConfig);
        authHeader.addOAuthParameter("callback", callbackURL);

        try {
            authHeader.sign("POST", REQUEST_TOKEN_URL);
        } catch (Exception e) {
            // TODO logging
            e.printStackTrace();
            return false;
        }

        try {
            PostMethod requestTokenMethod = new PostMethod(REQUEST_TOKEN_URL);
            requestTokenMethod.setRequestHeader("Host", "api.twitter.com");
            requestTokenMethod.setRequestHeader("User-Agent", userAgent);
            requestTokenMethod.setRequestHeader("Authorization", authHeader.toHeaderString());

            int responseCode = httpClient.executeMethod(requestTokenMethod);
            String responseBody = requestTokenMethod.getResponseBodyAsString();

            if (responseCode >= 400) {
                JSONObject jsonObject = (JSONObject) JSONValue.parse(responseBody);

                if (jsonObject.containsKey("errors")) {
                    JSONArray errors = (JSONArray) jsonObject.get("errors");
                    throw new TwitterException(errors.toString());
                } else {
                    throw new TwitterException("Twitter API returned response code: " + responseCode);
                }
            } else {
                Map response = parseEncodedResponse(responseBody);
                String token = (String) response.get("oauth_token");
                String secret = (String) response.get("oauth_token_secret");
                this.token = new RequestToken(token, secret);
                return true;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean fetchAccessToken(String oauthVerifier) throws TwitterException, TokenException {
        if (token != null && token instanceof AccessToken) {
            throw new TokenException("Already have access token.");
        } else if (token == null || !(token instanceof RequestToken)) {
            throw new TokenException("Request token not present.");
        }

        OAuthHeader authHeader = new OAuthHeader(oauthConfig, token);
        authHeader.addOAuthParameter("verifier", oauthVerifier);
        try {
            authHeader.sign("POST", ACCESS_TOKEN_URL);
        } catch (Exception e) {
            // TODO logging
            e.printStackTrace();
        }

        try {
            PostMethod accessTokenMethod = new PostMethod(ACCESS_TOKEN_URL);
            accessTokenMethod.setRequestHeader("Host", "api.twitter.com");
            accessTokenMethod.setRequestHeader("User-Agent", userAgent);
            accessTokenMethod.setRequestHeader("Authorization", authHeader.toHeaderString());

            int responseCode = httpClient.executeMethod(accessTokenMethod);
            String responseBody = accessTokenMethod.getResponseBodyAsString();

            if (responseCode >= 400) {
                JSONObject jsonObject = (JSONObject) JSONValue.parse(responseBody);

                if (jsonObject.containsKey("errors")) {
                    JSONArray errors = (JSONArray) jsonObject.get("errors");
                    throw new TwitterException(errors.toString());
                } else {
                    throw new TwitterException("Twitter API returned response code: " + responseCode);
                }
            } else {
                Map response = parseEncodedResponse(responseBody);
                String token = (String) response.get("oauth_token");
                String secret = (String) response.get("oauth_token_secret");
                long userId = Long.parseLong((String) response.get("user_id"));
                String screenName = (String) response.get("screen_name");
                this.token = new AccessToken(token, secret, userId, screenName);
                return true;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public long uploadMedia(File file) throws TwitterException, TokenException {
        if (token == null || !(token instanceof AccessToken)) {
            throw new TokenException("Access token not present.");
        }

        OAuthHeader authHeader = new OAuthHeader(oauthConfig, token);

        try {
            authHeader.sign("POST", MEDIA_UPLOAD_URL);
        } catch (Exception e) {
            // TODO logging
            e.printStackTrace();
        }

        try {
            PostMethod mediaUploadMethod = new PostMethod(MEDIA_UPLOAD_URL);
            mediaUploadMethod.setRequestHeader("Host", "api.twitter.com");
            mediaUploadMethod.setRequestHeader("User-Agent", userAgent);
            mediaUploadMethod.setRequestHeader("Authorization", authHeader.toHeaderString());

            Part[] parts = {
                    new FilePart("media", file)
            };

            mediaUploadMethod.setRequestEntity(new MultipartRequestEntity(parts, mediaUploadMethod.getParams()));
            int responseCode = httpClient.executeMethod(mediaUploadMethod);

            String responseBody = mediaUploadMethod.getResponseBodyAsString();
            JSONObject jsonObject = (JSONObject) JSONValue.parse(responseBody);

            if (responseCode >= 400) {
                if (jsonObject.containsKey("errors")) {
                    JSONArray errors = (JSONArray) jsonObject.get("errors");
                    throw new TwitterException(errors.toString());
                } else {
                    throw new TwitterException("Twitter API returned response code: " + responseCode);
                }
            } else {
                Long mediaId = (Long) jsonObject.get("media_id");
                return mediaId != null ? mediaId.longValue() : -1;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return 0;
    }

    public long updateStatus(String message, long[] mediaIds) throws TwitterException, TokenException, UnsupportedEncodingException {
        if (token == null || !(token instanceof AccessToken)) {
            throw new TokenException("Access token not present.");
        }

        List parameters = new ArrayList();
        parameters.add(new NameValuePair("status", message));

        if (mediaIds.length > 0) {
            parameters.add(new NameValuePair("media_ids", joinIds(mediaIds)));

        }

        OAuthHeader authHeader = new OAuthHeader(oauthConfig, token);

        Iterator iterator = parameters.iterator();
        while (iterator.hasNext()) {
            NameValuePair pair = (NameValuePair) iterator.next();
            authHeader.addParameter(pair.getName(), pair.getValue());
        }

        try {
            authHeader.sign("POST", UPDATE_STATUS_URL);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return -1;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return -1;
        }

        try {
            PostMethod updateStatusMethod = new PostMethod(UPDATE_STATUS_URL);
            updateStatusMethod.setRequestHeader("Host", "api.twitter.com");
            updateStatusMethod.setRequestHeader("User-Agent", userAgent);
            updateStatusMethod.setRequestHeader("Authorization", authHeader.toHeaderString());
            updateStatusMethod.addParameters((NameValuePair[]) parameters.toArray(new NameValuePair[parameters.size()]));

            int responseCode = httpClient.executeMethod(updateStatusMethod);
            String responseBody = updateStatusMethod.getResponseBodyAsString();
            JSONObject jsonObject = (JSONObject) JSONValue.parse(responseBody);

            if (responseCode >= 400) {
                if (jsonObject.containsKey("errors")) {
                    JSONArray errors = (JSONArray) jsonObject.get("errors");
                    throw new TwitterException(errors.toString());
                } else {
                    throw new TwitterException("Twitter API returned response code: " + responseCode);
                }
            } else {
                Long statusId = (Long) jsonObject.get("id");
                return statusId != null ? statusId.longValue() : -1;
            }
        } catch (HttpException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return -1;
    }

    private String joinIds(long[] mediaIds) {
        StringBuffer mediaIdsBuffer = new StringBuffer();

        for (int i = 0; i < mediaIds.length; i++) {
            mediaIdsBuffer.append(mediaIds[0]);

            if (i != mediaIds.length - 1) {
                mediaIdsBuffer.append(",");
            }
        }

        return mediaIdsBuffer.toString();
    }

    public URL getAuthenticateURL(String suggestedScreenName) throws TokenException {
        if (token == null || !(token instanceof RequestToken)) {
            throw new TokenException("Request token not present.");
        }

        Map parameters = new HashMap();

        if (suggestedScreenName != null) {
            parameters.put("screen_name", suggestedScreenName);
        }

        parameters.put("oauth_token", token.getToken());

        try {
            return getURI(AUTHORIZE_URL, parameters).toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private URI getURI(String baseURL, Map getParameters) {
        String paramString = "";

        if (getParameters != null && !getParameters.isEmpty()) {
            StringBuffer buffer = new StringBuffer();
            buffer.append("?");

            Iterator iterator = getParameters.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry entry = (Map.Entry) iterator.next();
                String key = (String) entry.getKey();
                String value = (String) entry.getValue();

                buffer.append(key);
                buffer.append("=");
                buffer.append(value);

                if (iterator.hasNext()) {
                    buffer.append("&");
                }
            }

            paramString = buffer.toString();
        }

        return URI.create(baseURL + paramString);
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
}
