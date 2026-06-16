package burp;

import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Bfunc.StatusCodeProc 的边界与健壮性测试。
 * 覆盖非法 state（null/空/非数字/不完整区间）不应抛异常。
 */
class StatusCodeProcTest {

    @Test
    void singleThreeDigitCode_parsed() {
        Collection<Integer> result = Bfunc.StatusCodeProc("200");
        assertEquals(1, result.size());
        assertTrue(result.contains(200));
    }

    @Test
    void nullState_returnsEmpty_notCrash() {
        // 之前会 NPE（state.length()）
        Collection<Integer> result = Bfunc.StatusCodeProc(null);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void emptyState_returnsEmpty_notCrash() {
        assertTrue(Bfunc.StatusCodeProc("").isEmpty());
        assertTrue(Bfunc.StatusCodeProc("   ").isEmpty());
    }

    @Test
    void nonNumericState_returnsEmpty_notCrash() {
        // 之前会 NumberFormatException（"abc" 走 else 分支 Integer.valueOf("abc")）
        assertTrue(Bfunc.StatusCodeProc("abc").isEmpty());
    }

    @Test
    void incompleteRange_returnsEmpty_notCrash() {
        // "200-" 之前会 Integer.parseInt("") 抛 NFE
        assertTrue(Bfunc.StatusCodeProc("200-").isEmpty());
        assertTrue(Bfunc.StatusCodeProc("-300").isEmpty());
    }

    @Test
    void trailingComma_handled() {
        // "200," 之前会 Integer.valueOf("") 抛 NFE
        Collection<Integer> result = Bfunc.StatusCodeProc("200,");
        // 逗号分支：200 是合法 3 位，被加入；末尾空段被忽略
        assertEquals(1, result.size());
        assertTrue(result.contains(200));
    }

    @Test
    void commaSeparatedCodes_parsed() {
        Collection<Integer> result = Bfunc.StatusCodeProc("200,301,404");
        assertEquals(3, result.size());
        assertTrue(result.contains(200));
        assertTrue(result.contains(301));
        assertTrue(result.contains(404));
    }

    @Test
    void range_parsed() {
        Collection<Integer> result = Bfunc.StatusCodeProc("200-202");
        assertEquals(3, result.size());
        assertTrue(result.contains(200));
        assertTrue(result.contains(201));
        assertTrue(result.contains(202));
    }

    @Test
    void commaWithRange_parsed() {
        Collection<Integer> result = Bfunc.StatusCodeProc("200,300-302");
        assertTrue(result.contains(200));
        assertTrue(result.contains(300));
        assertTrue(result.contains(301));
        assertTrue(result.contains(302));
    }

    @Test
    void mixedValidAndInvalid_doesNotCrash() {
        // 混入非法段，整体不应崩（非法段被跳过或整体回退空集合）
        assertDoesNotThrow(() -> Bfunc.StatusCodeProc("200,abc,301"));
    }

    @Test
    void whitespaceAroundCode_trimmed() {
        Collection<Integer> result = Bfunc.StatusCodeProc(" 200 ");
        assertTrue(result.contains(200));
    }
}
