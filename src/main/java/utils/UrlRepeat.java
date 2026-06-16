package utils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UrlRepeat {
    // 用 ConcurrentHashMap 避免 HTTP 回调线程并发 put 时损坏 HashMap 结构；
    // check+add 的原子性由 putIfAbsent 保证（见 addMethodAndUrl）。
    private Map<String, Integer> MethodAndUrlMap = new ConcurrentHashMap<>();

    public Map<String, Integer> getRequestMethodAndUrlMap() {
        return this.MethodAndUrlMap;
    }

    public void clear() {
        getRequestMethodAndUrlMap().clear();
    }

    public void addMethodAndUrl(String Method, String url) {
        if (Method == null || Method.length() <= 0)
            throw new IllegalArgumentException("Request method cannot be empty");
        if (url == null || url.length() <= 0)
            throw new IllegalArgumentException("Url cannot be empty");
        getRequestMethodAndUrlMap().putIfAbsent(String.valueOf(Method) + " " + url, Integer.valueOf(1));
    }

    public boolean check(String Method, String url) {
        if (getRequestMethodAndUrlMap().get(String.valueOf(Method) + " " + url) != null)
            return true;
        return false;
    }

    /**
     * 原子地"标记并判断是否首次"：若 key 已存在返回 false（已扫过），否则放入并返回 true。
     * 用 putIfAbsent 保证并发下 check-then-act 的原子性，避免两个线程同时通过 check。
     */
    public boolean markIfAbsent(String Method, String url) {
        if (Method == null || Method.length() <= 0)
            throw new IllegalArgumentException("Request method cannot be empty");
        if (url == null || url.length() <= 0)
            throw new IllegalArgumentException("Url cannot be empty");
        return getRequestMethodAndUrlMap().putIfAbsent(String.valueOf(Method) + " " + url, Integer.valueOf(1)) == null;
    }

    public String RemoveUrlParameterValue(String url) {
        try {
            String urlQuery = (new URL(url)).getQuery();
            if (urlQuery == null) {
//                Object obj = "";
                return url;
            }
            String newUrl = String.valueOf(url.replace(urlQuery, "")) + RemoveParameterValue(urlQuery);
            String str = newUrl;
            return newUrl;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private String RemoveParameterValue(String urlQuery) {
        String parameter = "";
        String[] split = urlQuery.split("&");
        for (int i = 0; i < split.length; i++)
            parameter = String.valueOf(parameter) + split[i].split("=")[0] + "=&";
        return parameter.substring(0, parameter.length() - 1);
    }
}
