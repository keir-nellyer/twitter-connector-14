package uk.co.kyocera.twitter.connector.oauth;

import org.apache.commons.codec.binary.Base64;
import uk.co.kyocera.twitter.connector.util.Util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class OAuthHeader {
    public static final String OAUTH_PARAMETER_PREFIX = "oauth_";
    private static final String OAUTH_HEADER_PREFIX = "OAuth ";
    private static final String OAUTH_VERSION = "1.0";
    private static final String SIGNING_METHOD = "HmacSHA1";

    private final OAuthConfig oauthConfig;
    private final Token token;

    private final Map parameters = new HashMap();

    public OAuthHeader(OAuthConfig oauthConfig) {
        this.oauthConfig = oauthConfig;
        this.token = null;
    }

    public OAuthHeader(OAuthConfig oauthConfig, Token token) {
        this.oauthConfig = oauthConfig;
        this.token = token;
    }

    public boolean isSigned() {
        return parameters.containsKey(OAUTH_PARAMETER_PREFIX + "signature");
    }

    public void addOAuthParameter(String key, String value) {
        addParameter(OAUTH_PARAMETER_PREFIX + key, value);
    }

    public void addParameter(String key, String value) {
        checkModifiable();
        parameters.put(key, value);
    }

    private void timestamp() {
        long epochSeconds = System.currentTimeMillis() / 1000;
        addOAuthParameter("timestamp", String.valueOf(epochSeconds));
    }

    public void sign(String method, String baseURL) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
        checkModifiable();
        timestamp();
        addOAuthParameter("consumer_key", oauthConfig.getKey());
        addOAuthParameter("nonce", generateNonce());
        addOAuthParameter("signature_method", "HMAC-SHA1");
        addOAuthParameter("version", OAUTH_VERSION);

        if (token != null) {
            addOAuthParameter("token", token.getToken());
        }

        Map signingParameters = getEncodedParameters(parameters);
        // sort parameters by values and keys so they are in the correct order for signing
        signingParameters = Util.sortByValue(signingParameters);
        signingParameters = Util.sortByKey(signingParameters);

        String parameterString = getParameterString(signingParameters, "&");
        String baseSignature = getBaseSignature(method, baseURL, parameterString);
        String signature = computeSignature(getRawSigningKey(), baseSignature);
        addOAuthParameter("signature", signature);
    }

    private String getRawSigningKey() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(Util.percentEncode(oauthConfig.getSecret()));
        buffer.append("&");

        if (token != null) {
            buffer.append(Util.percentEncode(token.getSecret()));
        }

        return buffer.toString();
    }

    private String getBaseSignature(String method, String baseURL, String paramString) {
        return method.toUpperCase() + "&" + Util.percentEncode(baseURL) + "&" + Util.percentEncode(paramString);
    }

    /**
     * Generate a random nonce.
     * @return the nonce
     */
    private String generateNonce() {
        // super simple and quick way to generate nonce (slightly more secure than System.currentTimeMillis())
        return Long.toHexString(Double.doubleToLongBits(Math.random()));
    }

    private void checkModifiable() {
        if (isSigned()) {
            throw new IllegalStateException("Header already signed, this operation would modify the contents.");
        }
    }

    public String toHeaderString() {
        return OAUTH_HEADER_PREFIX + getParameterString(getEncodedParameters(parameters), ", ");
    }

    /**
     * Signs a {@link String} using HMAC-SHA1 with the provided signing key
     * @param key the signing key
     * @param data the data
     * @return the signed data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static String computeSignature(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        byte[] keyBytes = key.getBytes();
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, SIGNING_METHOD);

        Mac mac = Mac.getInstance(SIGNING_METHOD);
        mac.init(signingKey);

        byte[] rawHmac = mac.doFinal(data.getBytes());
        byte[] base64 = Base64.encodeBase64(rawHmac);

        return new String(base64, "UTF-8").trim();
    }

    /**
     * Encodes all parameters and returns them in a new {@link HashMap}.
     *
     * @param parameters the parameters
     * @return the encoded parameters
     */
    private static Map getEncodedParameters(Map parameters) {
        Map encodedParameters = new HashMap();

        Iterator iterator = parameters.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();

            encodedParameters.put(Util.percentEncode(key), Util.percentEncode(value));
        }

        return encodedParameters;
    }

    /**
     * Concatenates all parameters into a single string using the defined deliminator.
     *
     * @param parameters the parameters
     * @return the parameter string
     */
    private static String getParameterString(Map parameters, String deliminator) {
        StringBuffer buffer = new StringBuffer();
        Iterator iterator = parameters.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();

            buffer.append(key);
            buffer.append("=");
            buffer.append(value);

            if (iterator.hasNext()) {
                buffer.append(deliminator);
            }
        }

        return buffer.toString();
    }
}
