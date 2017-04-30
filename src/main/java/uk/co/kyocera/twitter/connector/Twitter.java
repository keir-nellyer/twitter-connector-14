package uk.co.kyocera.twitter.connector;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import uk.co.kyocera.twitter.connector.oauth.OAuthConfig;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;

public class Twitter {
    private static final String REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token";

    private static final String HMAC_SHA1 = "HmacSHA1";

    private final String userAgent;
    private final OAuthConfig oauthConfig;

    private String oauthTokenSecret = null;

    public Twitter(String userAgent, OAuthConfig oauthConfig) {
        this.userAgent = userAgent;
        this.oauthConfig = oauthConfig;
    }

    public void fetchRequestToken() {
        long timeMillis = System.currentTimeMillis();
        long timeSecs = timeMillis / 1000;

        Map authHeader = new HashMap();
        authHeader.put("oauth_nonce", String.valueOf(timeMillis)); // use time millis for ease
        authHeader.put("oauth_callback", "http://127.0.0.1:8080/process_callback");
        authHeader.put("oauth_signature_method", "HMAC-SHA1");
        authHeader.put("oauth_timestamp", String.valueOf(timeSecs));
        authHeader.put("oauth_consumer_key", oauthConfig.getKey());
        authHeader.put("oauth_version", "1.0");

        authHeader = sortByValue(authHeader);
        authHeader = sortByKey(authHeader);

        String parameterString = getParameterString(authHeader);
        System.out.println("Parm str: " + parameterString);
        String baseSignature = getBaseAuthSignature("POST", REQUEST_TOKEN_URL, parameterString);
        System.out.println("Base Signature: " + baseSignature);
        String signingKey = getSigningKey();
        System.out.println("Signing Key: " + signingKey);
        String hashed = hash(signingKey, baseSignature);
        System.out.println("Hash: " + hashed);
        authHeader.put("oauth_signature", hashed);

        HttpsURLConnection connection = null;

        try {
            URL url = new URL(REQUEST_TOKEN_URL);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Host", "api.twitter.com");
            connection.setRequestProperty("User-Agent", userAgent);
            String header = getHeader(authHeader);
            System.out.println("Header: " + header);
            connection.setRequestProperty("Authorization", "OAuth " + header);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
            connection.setUseCaches(false);

            writeRequest(connection, "");

            // Parse the JSON response into a JSON mapped object to fetch fields from.
            String response = readResponse(connection);
            System.out.println("Response: " + response);
            JSONObject obj = (JSONObject)JSONValue.parse(response);

            if (obj != null) {
                String token = (String)obj.get("oauth_token");
                String secret = (String) obj.get("oauth_token_secret");

                System.out.println(token);
                System.out.println(secret);
            } else {

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
    }

    private static Map sortByKey(Map map) {
        return new TreeMap(map);
    }

    private static Map sortByValue(Map map) {
        List list = new LinkedList(map.entrySet());

        Collections.sort(list, new Comparator() {
            public int compare(Object o1, Object o2) {
                Comparable comparable1 = (Comparable) ((Map.Entry) o1).getValue();
                Comparable comparable2 = (Comparable) ((Map.Entry) o2).getValue();

                return comparable1.compareTo(comparable2);
            }
        });

        Map sortedMap = new LinkedHashMap();
        for (Iterator iterator = list.iterator(); iterator.hasNext();) {
            Map.Entry entry = (Map.Entry) iterator.next();
            sortedMap.put(entry.getKey(), entry.getValue());
        }

        return sortedMap;
    }

    private String getHeader(Map parameters) {
        StringBuffer buffer = new StringBuffer();
        Iterator iterator = parameters.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();

            buffer.append(percentEncode(key));
            buffer.append("=\"");
            buffer.append(percentEncode(value));
            buffer.append("\"");

            if (iterator.hasNext()) {
                buffer.append(", ");
            }
        }

        return buffer.toString();
    }

    private String getParameterString(Map parameters) {
        StringBuffer buffer = new StringBuffer();
        Iterator iterator = parameters.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();

            buffer.append(percentEncode(key));
            buffer.append("=");
            buffer.append(percentEncode(value));

            if (iterator.hasNext()) {
                buffer.append("&");
            }
        }

        return buffer.toString();
    }

    private String getBaseAuthSignature(String method, String baseURL, String paramString) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(method.toUpperCase());
        buffer.append("&");
        buffer.append(percentEncode(baseURL));
        buffer.append("&");
        buffer.append(percentEncode(paramString));
        return buffer.toString();
    }

    private String getSigningKey() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(percentEncode(oauthConfig.getSecret()));
        buffer.append("&");

        if (oauthTokenSecret != null) {
            buffer.append(percentEncode(oauthTokenSecret));
        }

        return buffer.toString();
    }

    private String hash(String key, String data) {
        try {
            // Get an hmac_sha1 key from the raw key bytes
            byte[] keyBytes = key.getBytes();
            SecretKeySpec signingKey = new SecretKeySpec(keyBytes, HMAC_SHA1);

            // Get an hmac_sha1 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance(HMAC_SHA1);
            mac.init(signingKey);

            // Compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes());

            // Convert raw bytes to base64
            byte[] base64 = Base64.encodeBase64(rawHmac);
            //byte[] hexBytes = new Hex().encode(rawHmac);

            //  Covert array of Hex bytes to a String
            return new String(base64, "UTF-8").trim();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String percentEncode(String s) {
        if (s == null) {
            return "";
        }
        try {
            return URLEncoder.encode(s, "UTF-8")
                    // OAuth encodes some characters differently:
                    .replaceAll("\\+", "%20")
                    .replaceAll("\\*", "%2A")
                    .replaceAll("%7E", "~");
            // This could be done faster with more hand-crafted code.
        } catch (UnsupportedEncodingException wow) {
            throw new RuntimeException(wow.getMessage(), wow);
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
        catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    // Reads a response for a given connection and returns it as a string.
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
            String line = "";
            while((line = br.readLine()) != null) {
                str.append(line + System.getProperty("line.separator"));
            }
            return str.toString();
        }
        catch (IOException e) {
            e.printStackTrace();
            return new String();
        }
    }
}
