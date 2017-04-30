package uk.co.kyocera.twitter.connector.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URLEncoder;
import java.util.*;

public class Util {
    private static final String HMAC_SHA1 = "HmacSHA1";

    public static Map sortByKey(Map map) {
        return new TreeMap(map);
    }

    public static Map sortByValue(Map map) {
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

    public static String hmacSha1(String key, String data) {
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
            byte[] base64 = org.apache.commons.codec.binary.Base64.encodeBase64(rawHmac);
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
}
