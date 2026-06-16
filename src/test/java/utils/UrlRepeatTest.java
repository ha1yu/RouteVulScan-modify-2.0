package utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * UrlRepeat 测试，重点覆盖 markIfAbsent 的原子语义与去重行为。
 */
class UrlRepeatTest {

    @Test
    void markIfAbsent_firstCallReturnsTrue() {
        UrlRepeat u = new UrlRepeat();
        assertTrue(u.markIfAbsent("GET", "http://a.com/x"));
    }

    @Test
    void markIfAbsent_secondCallSameKeyReturnsFalse() {
        UrlRepeat u = new UrlRepeat();
        assertTrue(u.markIfAbsent("GET", "http://a.com/x"));
        assertFalse(u.markIfAbsent("GET", "http://a.com/x"));
    }

    @Test
    void markIfAbsent_differentMethodTreatedAsDifferent() {
        UrlRepeat u = new UrlRepeat();
        assertTrue(u.markIfAbsent("GET", "http://a.com/x"));
        // 同 URL 不同方法视为不同条目
        assertTrue(u.markIfAbsent("POST", "http://a.com/x"));
    }

    @Test
    void markIfAbsent_differentUrlTreatedAsDifferent() {
        UrlRepeat u = new UrlRepeat();
        assertTrue(u.markIfAbsent("GET", "http://a.com/x"));
        assertTrue(u.markIfAbsent("GET", "http://a.com/y"));
    }

    @Test
    void check_reflectsMarkIfAbsent() {
        UrlRepeat u = new UrlRepeat();
        u.markIfAbsent("GET", "http://a.com/x");
        assertTrue(u.check("GET", "http://a.com/x"));
        assertFalse(u.check("GET", "http://a.com/y"));
    }

    @Test
    void clear_resetsAll() {
        UrlRepeat u = new UrlRepeat();
        u.markIfAbsent("GET", "http://a.com/x");
        u.clear();
        assertFalse(u.check("GET", "http://a.com/x"));
        // 清空后再次标记应返回 true
        assertTrue(u.markIfAbsent("GET", "http://a.com/x"));
    }

    @Test
    void markIfAbsent_emptyMethodThrows() {
        UrlRepeat u = new UrlRepeat();
        assertThrows(IllegalArgumentException.class, () -> u.markIfAbsent("", "http://a.com/x"));
        assertThrows(IllegalArgumentException.class, () -> u.markIfAbsent(null, "http://a.com/x"));
    }

    @Test
    void markIfAbsent_emptyUrlThrows() {
        UrlRepeat u = new UrlRepeat();
        assertThrows(IllegalArgumentException.class, () -> u.markIfAbsent("GET", ""));
        assertThrows(IllegalArgumentException.class, () -> u.markIfAbsent("GET", null));
    }

    @Test
    void removeUrlParameterValue_preservesPathWithoutQuery() {
        UrlRepeat u = new UrlRepeat();
        // 无 query 原样返回
        assertEquals("http://a.com/x", u.RemoveUrlParameterValue("http://a.com/x"));
    }

    @Test
    void removeUrlParameterValue_stripsParamValues() {
        UrlRepeat u = new UrlRepeat();
        String result = u.RemoveUrlParameterValue("http://a.com/x?a=1&b=2");
        // 参数值被清空，key 保留
        assertTrue(result.contains("a="));
        assertTrue(result.contains("b="));
        assertFalse(result.contains("a=1"));
        assertFalse(result.contains("b=2"));
    }
}
