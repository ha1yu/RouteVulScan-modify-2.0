package yaml;

import burp.BurpExtender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * YamlUtil 纯逻辑与文件读写测试。
 * 全部可离线运行，不依赖 Burp 运行时；MergerUpdateYamlFunc 等需要 Yaml_Path 的方法，
 * 通过反射把 BurpExtender.Yaml_Path 指向 @TempDir 下的临时文件来覆盖。
 */
class YamlUtilTest {

    @TempDir
    Path tempDir;

    private Path yamlFile;
    private String originalYamlPath;

    @BeforeEach
    void setUp() throws Exception {
        yamlFile = tempDir.resolve("Rules.yaml");
        // 备份并覆盖 BurpExtender.Yaml_Path，使 MergerUpdateYamlFunc/addYaml 等指向临时文件。
        originalYamlPath = BurpExtender.Yaml_Path;
        BurpExtender.Yaml_Path = yamlFile.toString();
    }

    @AfterEach
    void tearDown() throws Exception {
        // 还原 Yaml_Path，避免污染其他测试。
        BurpExtender.Yaml_Path = originalYamlPath;
    }

    // ---------- 纯函数 ----------

    @Test
    void defaultYamlData_containsAllKnownKeysWithDefaults() {
        Map<String, Object> data = YamlUtil.defaultYamlData();
        assertNotNull(data.get(YamlUtil.LOAD_LIST_KEY));
        assertNotNull(data.get(YamlUtil.HOST_FILTER_KEY));
        assertNotNull(data.get(YamlUtil.BLACK_HOST_KEY));
        assertInstanceOf(List.class, data.get(YamlUtil.LOAD_LIST_KEY));
        assertEquals("*", data.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("", data.get(YamlUtil.BLACK_HOST_KEY));
        assertTrue(((List<?>) data.get(YamlUtil.LOAD_LIST_KEY)).isEmpty());
    }

    @Test
    void readHostFilter_returnsValueWhenPresent() {
        Map<String, Object> data = new HashMap<>();
        data.put(YamlUtil.HOST_FILTER_KEY, "*.example.com");
        assertEquals("*.example.com", YamlUtil.readHostFilter(data, "*"));
    }

    @Test
    void readHostFilter_returnsFallbackWhenMissing() {
        Map<String, Object> data = new HashMap<>();
        assertEquals("*", YamlUtil.readHostFilter(data, "*"));
    }

    @Test
    void readHostFilter_returnsFallbackWhenBlank() {
        Map<String, Object> data = new HashMap<>();
        data.put(YamlUtil.HOST_FILTER_KEY, "   ");
        assertEquals("fallback", YamlUtil.readHostFilter(data, "fallback"));
    }

    @Test
    void readHostFilter_returnsFallbackWhenNullMap() {
        assertEquals("def", YamlUtil.readHostFilter(null, "def"));
    }

    @Test
    void readBlackHost_returnsValueWhenPresent() {
        Map<String, Object> data = new HashMap<>();
        data.put(YamlUtil.BLACK_HOST_KEY, "a.com,b.com");
        assertEquals("a.com,b.com", YamlUtil.readBlackHost(data, ""));
    }

    @Test
    void readBlackHost_returnsValueWhenBlank() {
        // 黑名单允许空串（与白名单不同：白名单空串走 fallback，黑名单空串是合法值）
        Map<String, Object> data = new HashMap<>();
        data.put(YamlUtil.BLACK_HOST_KEY, "");
        assertEquals("", YamlUtil.readBlackHost(data, "fallback"));
    }

    @Test
    void readBlackHost_returnsFallbackWhenMissing() {
        Map<String, Object> data = new HashMap<>();
        assertEquals("fallback", YamlUtil.readBlackHost(data, "fallback"));
    }

    @Test
    void readStrYaml_preservesAllTopLevelKeys() {
        String yaml = "filter_host: '*.test.com'\n"
                + "black_host: 'bad.com'\n"
                + "Load_List:\n"
                + "  - {id: 1, name: rule1, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n";
        Map<String, Object> data = YamlUtil.readStrYaml(yaml);
        assertEquals("*.test.com", data.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("bad.com", data.get(YamlUtil.BLACK_HOST_KEY));
        assertInstanceOf(List.class, data.get(YamlUtil.LOAD_LIST_KEY));
        assertEquals(1, ((List<?>) data.get(YamlUtil.LOAD_LIST_KEY)).size());
    }

    @Test
    void readStrYaml_fillsDefaultsWhenKeysMissing() {
        // 旧版 Rules.yaml 只有 Load_List，host key 应被补默认值
        String yaml = "Load_List:\n"
                + "  - {id: 1, name: rule1, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n";
        Map<String, Object> data = YamlUtil.readStrYaml(yaml);
        assertEquals("*", data.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("", data.get(YamlUtil.BLACK_HOST_KEY));
    }

    @Test
    void readStrYaml_handlesEmptyLoadList() {
        String yaml = "filter_host: '*'\nblack_host: ''\nLoad_List: []\n";
        Map<String, Object> data = YamlUtil.readStrYaml(yaml);
        assertInstanceOf(List.class, data.get(YamlUtil.LOAD_LIST_KEY));
        assertTrue(((List<?>) data.get(YamlUtil.LOAD_LIST_KEY)).isEmpty());
    }

    // ---------- 文件读写 round-trip ----------

    @Test
    void writeYaml_thenReadYaml_preservesAllTopLevelKeys() {
        Map<String, Object> data = YamlUtil.readStrYaml(
                "filter_host: '*.keep.com'\n"
                        + "black_host: 'drop.com'\n"
                        + "Load_List:\n"
                        + "  - {id: 1, name: rule1, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n");
        YamlUtil.writeYaml(data, yamlFile.toString());

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.keep.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("drop.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
        assertEquals(1, ((List<?>) readBack.get(YamlUtil.LOAD_LIST_KEY)).size());
    }

    @Test
    void readYaml_nonExistentFile_createsDefaultAndWritesIt() {
        Path missing = tempDir.resolve("new.yaml");
        Map<String, Object> data = YamlUtil.readYaml(missing.toString());
        // 读不存在的文件应返回默认结构
        assertEquals("*", data.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("", data.get(YamlUtil.BLACK_HOST_KEY));
        // 同时应把默认结构写入文件
        assertTrue(missing.toFile().exists());
    }

    @Test
    void writeHostLists_preservesLoadList() {
        // 先写一个有规则的文件
        Map<String, Object> data = YamlUtil.readStrYaml(
                "filter_host: '*'\nblack_host: ''\nLoad_List:\n"
                        + "  - {id: 1, name: rule1, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n"
                        + "  - {id: 2, name: rule2, url: /b, re: bar, info: baz, state: '200', method: GET, type: default, loaded: true}\n");
        YamlUtil.writeYaml(data, yamlFile.toString());

        // 写黑白名单，不应影响 Load_List
        YamlUtil.writeHostLists(yamlFile.toString(), "*.new.com", "x.com,y.com");

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.new.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("x.com,y.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
        assertEquals(2, ((List<?>) readBack.get(YamlUtil.LOAD_LIST_KEY)).size());
    }

    @Test
    void writeHostLists_nullValuesBecomeDefaults() {
        YamlUtil.writeHostLists(yamlFile.toString(), null, null);
        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("", readBack.get(YamlUtil.BLACK_HOST_KEY));
    }

    @Test
    void writeYaml_emitsHostKeysBeforeLoadListRegardlessOfInputOrder() throws Exception {
        // 旧格式文件只有 Load_List，读出后 host key 被补到末尾。
        // writeYaml 必须保证输出顺序为 filter_host、black_host、Load_List。
        YamlUtil.writeYaml(YamlUtil.readStrYaml("Load_List:\n  - {id: 1, name: r}\n"), yamlFile.toString());

        List<String> lines = java.nio.file.Files.readAllLines(yamlFile);
        int filterIdx = -1, blackIdx = -1, loadIdx = -1;
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (l.startsWith("filter_host:")) filterIdx = i;
            else if (l.startsWith("black_host:")) blackIdx = i;
            else if (l.startsWith("Load_List:")) loadIdx = i;
        }
        assertTrue(filterIdx >= 0 && blackIdx >= 0 && loadIdx >= 0, "三个 key 都应存在");
        assertTrue(filterIdx < blackIdx, "filter_host 应在 black_host 之前");
        assertTrue(blackIdx < loadIdx, "black_host 应在 Load_List 之前");
    }

    @Test
    void writeHostLists_updatesExistingValuesInPlace() throws Exception {
        // 文件头部已有 host key，保存后应原地更新（不重复、不追加到末尾），值正确。
        Map<String, Object> data = YamlUtil.readStrYaml(
                "filter_host: '*'\nblack_host: 'old.com'\nLoad_List: []\n");
        YamlUtil.writeYaml(data, yamlFile.toString());

        YamlUtil.writeHostLists(yamlFile.toString(), "*.new.com", "a.com,b.com,c.com");

        List<String> lines = java.nio.file.Files.readAllLines(yamlFile);
        long filterCount = lines.stream().filter(l -> l.startsWith("filter_host:")).count();
        long blackCount = lines.stream().filter(l -> l.startsWith("black_host:")).count();
        assertEquals(1, filterCount, "filter_host 不应重复");
        assertEquals(1, blackCount, "black_host 不应重复");

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.new.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("a.com,b.com,c.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
    }

    // ---------- 编辑规则不丢黑白名单（关键回归点）----------

    @Test
    void addYaml_preservesHostKeys() {
        seedFileWithHostKeys();
        Map<String, Object> newRule = newRule(99, "added");
        YamlUtil.addYaml(newRule, yamlFile.toString());

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.orig.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("orig-black.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
        assertEquals(3, ((List<?>) readBack.get(YamlUtil.LOAD_LIST_KEY)).size());
    }

    @Test
    void updateYaml_preservesHostKeys() {
        seedFileWithHostKeys();
        Map<String, Object> updated = newRule(1, "renamed");
        YamlUtil.updateYaml(updated, yamlFile.toString());

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.orig.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("orig-black.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
        // 数量不变（id=1 被替换）
        List<?> list = (List<?>) readBack.get(YamlUtil.LOAD_LIST_KEY);
        assertEquals(2, list.size());
        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) list.get(0);
        assertEquals("renamed", first.get("name"));
    }

    @Test
    void removeYaml_preservesHostKeys() {
        seedFileWithHostKeys();
        YamlUtil.removeYaml("1", yamlFile.toString());

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.orig.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("orig-black.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
        assertEquals(1, ((List<?>) readBack.get(YamlUtil.LOAD_LIST_KEY)).size());
    }

    // ---------- ifmapEqual null 安全与对称性 ----------

    @Test
    void ifmapEqual_nullSafeOnLeftNullValue() {
        // 之前会 NPE：左侧 method=null，调用 null.equals(...) 触发崩溃
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("name", "x");
        a.put("method", null);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("name", "x");
        b.put("method", "GET");
        // 不应抛 NPE，且应判定为不等
        assertDoesNotThrow(() -> YamlUtil.ifmapEqual(a, b));
        assertFalse(YamlUtil.ifmapEqual(a, b));
    }

    @Test
    void ifmapEqual_nullSafeOnBothNull() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("name", "x");
        a.put("method", null);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("name", "x");
        b.put("method", null);
        assertDoesNotThrow(() -> YamlUtil.ifmapEqual(a, b));
        assertTrue(YamlUtil.ifmapEqual(a, b));
    }

    @Test
    void ifmapEqual_symmetricWhenRightHasExtraKey() {
        // 非对称缺陷回归：右侧多一个字段，旧版只遍历左侧会误判相等
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("name", "x");
        a.put("url", "/a");
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("name", "x");
        b.put("url", "/a");
        b.put("info", "extra"); // 右侧独有
        assertFalse(YamlUtil.ifmapEqual(a, b), "右侧独有字段应导致判等失败（对称性）");
    }

    @Test
    void ifmapEqual_ignoresLoadedIdType() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("name", "x");
        a.put("url", "/a");
        a.put("re", "foo");
        a.put("loaded", true);
        a.put("id", 1);
        a.put("type", "g1");
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("name", "x");
        b.put("url", "/a");
        b.put("re", "foo");
        b.put("loaded", false);   // 不同
        b.put("id", 999);          // 不同
        b.put("type", "g2");       // 不同
        assertTrue(YamlUtil.ifmapEqual(a, b), "loaded/id/type 不参与判等");
    }

    @Test
    void inYamlList_findsExistingRule() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("name", "x");
        a.put("url", "/a");
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(a);

        Map<String, Object> query = new LinkedHashMap<>();
        query.put("name", "x");
        query.put("url", "/a");
        assertTrue(YamlUtil.inYamlList(list, query));
    }

    // ---------- MergerUpdateYamlFunc：云端覆盖黑白名单 + 只增不覆盖规则 ----------

    @Test
    void mergerUpdate_cloudHostKeysOverrideLocal() {
        seedFileWithHostKeys(); // 本地白名单 *.orig.com / 黑名单 orig-black.com

        // 云端 YAML 带 host key
        Map<String, Object> cloud = YamlUtil.readStrYaml(
                "filter_host: '*.cloud.com'\n"
                        + "black_host: 'cloud-black.com'\n"
                        + "Load_List: []\n");
        YamlUtil.MergerUpdateYamlFunc(cloud);

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.cloud.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("cloud-black.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
    }

    @Test
    void mergerUpdate_preservesLocalHostKeysWhenCloudMissingThem() {
        seedFileWithHostKeys();

        // 云端 YAML 不带 host key（只有 Load_List），本地应保留
        Map<String, Object> cloud = YamlUtil.readStrYaml(
                "Load_List: []\n");
        YamlUtil.MergerUpdateYamlFunc(cloud);

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        assertEquals("*.orig.com", readBack.get(YamlUtil.HOST_FILTER_KEY));
        assertEquals("orig-black.com", readBack.get(YamlUtil.BLACK_HOST_KEY));
    }

    @Test
    void mergerUpdate_appendsNewRulesWithoutDuplicates() {
        seedFileWithHostKeys(); // 本地有 id=1(name=x,url=/a) 和 id=2

        // 云端有一条全新规则 + 一条与本地重复的规则
        Map<String, Object> cloud = YamlUtil.readStrYaml(
                "filter_host: '*'\n"
                        + "black_host: ''\n"
                        + "Load_List:\n"
                        + "  - {id: 1, name: x, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n"
                        + "  - {id: 50, name: newrule, url: /new, re: nr, info: ni, state: '200', method: GET, type: default, loaded: true}\n");
        YamlUtil.MergerUpdateYamlFunc(cloud);

        Map<String, Object> readBack = YamlUtil.readYaml(yamlFile.toString());
        List<?> list = (List<?>) readBack.get(YamlUtil.LOAD_LIST_KEY);
        // 本地原有 2 条 + 云端新增 1 条（重复那条不追加）= 3 条
        assertEquals(3, list.size());
    }

    @Test
    void mergerUpdate_idTypeAsStringDoesNotCrash() {
        // 之前 MergerUpdateYamlFunc 里 (int) zidian.get("id") 遇到字符串 id 会 CCE
        seedFileWithIdAsString();
        Map<String, Object> cloud = YamlUtil.readStrYaml(
                "Load_List:\n"
                        + "  - {id: 1, name: brandnew, url: /bn, re: r, info: i, state: '200', method: GET, type: default, loaded: true}\n");
        assertDoesNotThrow(() -> YamlUtil.MergerUpdateYamlFunc(cloud));
    }

    // ---------- 辅助方法 ----------

    /** 写一个带黑白名单和 2 条规则的文件。 */
    private void seedFileWithHostKeys() {
        Map<String, Object> data = YamlUtil.readStrYaml(
                "filter_host: '*.orig.com'\n"
                        + "black_host: 'orig-black.com'\n"
                        + "Load_List:\n"
                        + "  - {id: 1, name: x, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n"
                        + "  - {id: 2, name: y, url: /b, re: bar, info: baz, state: '200', method: GET, type: default, loaded: true}\n");
        YamlUtil.writeYaml(data, yamlFile.toString());
    }

    /** 写一个 id 为字符串类型的文件，用于触发旧版 CCE 路径。 */
    private void seedFileWithIdAsString() {
        Map<String, Object> data = YamlUtil.readStrYaml(
                "filter_host: '*'\n"
                        + "black_host: ''\n"
                        + "Load_List:\n"
                        + "  - {id: '1', name: x, url: /a, re: foo, info: bar, state: '200', method: GET, type: default, loaded: true}\n");
        YamlUtil.writeYaml(data, yamlFile.toString());
    }

    private static Map<String, Object> newRule(int id, String name) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("id", id);
        rule.put("name", name);
        rule.put("url", "/a");
        rule.put("re", "foo");
        rule.put("info", "bar");
        rule.put("state", "200");
        rule.put("method", "GET");
        rule.put("type", "default");
        rule.put("loaded", true);
        return rule;
    }
}
