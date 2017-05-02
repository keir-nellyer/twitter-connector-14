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
