package uk.co.kyocera.twitter.connector.util;

import java.util.*;

public class Util {
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
}
