package burp;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BurpExtender.parseBlacklist 的反射测试。
 * 该方法是 private static，通过反射调用，不依赖 Burp 运行时。
 */
class ParseBlacklistTest {

    @SuppressWarnings("unchecked")
    private Set<String> parseBlacklist(String input) throws Exception {
        Method m = BurpExtender.class.getDeclaredMethod("parseBlacklist", String.class);
        m.setAccessible(true);
        return (Set<String>) m.invoke(null, input);
    }

    @Test
    void nullInput_returnsEmpty() throws Exception {
        assertTrue(parseBlacklist(null).isEmpty());
    }

    @Test
    void blankInput_returnsEmpty() throws Exception {
        assertTrue(parseBlacklist("").isEmpty());
        assertTrue(parseBlacklist("   ").isEmpty());
    }

    @Test
    void singleEntry_parsed() throws Exception {
        Set<String> result = parseBlacklist("evil.com");
        assertEquals(1, result.size());
        assertTrue(result.contains("evil.com"));
    }

    @Test
    void multipleEntries_parsed() throws Exception {
        Set<String> result = parseBlacklist("a.com,b.com,c.com");
        assertEquals(3, result.size());
        assertTrue(result.contains("a.com"));
        assertTrue(result.contains("b.com"));
        assertTrue(result.contains("c.com"));
    }

    @Test
    void whitespaceAroundEntries_trimmed() throws Exception {
        Set<String> result = parseBlacklist(" a.com , b.com ,c.com");
        assertTrue(result.contains("a.com"));
        assertTrue(result.contains("b.com"));
        assertTrue(result.contains("c.com"));
    }

    @Test
    void entriesLowercased() throws Exception {
        // 子串匹配忽略大小写的前提：解析时统一小写化
        Set<String> result = parseBlacklist("Evil.COM,BAD.Com");
        assertTrue(result.contains("evil.com"));
        assertTrue(result.contains("bad.com"));
        assertFalse(result.contains("Evil.COM"));
    }

    @Test
    void duplicatesRemoved() throws Exception {
        Set<String> result = parseBlacklist("a.com,a.com,b.com,b.com");
        assertEquals(2, result.size());
    }

    @Test
    void emptyEntriesBetweenCommas_ignored() throws Exception {
        Set<String> result = parseBlacklist("a.com,,,b.com,,");
        assertEquals(2, result.size());
        assertTrue(result.contains("a.com"));
        assertTrue(result.contains("b.com"));
    }

    @Test
    void trailingComma_handled() throws Exception {
        Set<String> result = parseBlacklist("a.com,b.com,");
        assertEquals(2, result.size());
    }
}
