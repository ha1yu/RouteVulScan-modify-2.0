package yaml;

import burp.BurpExtender;
import burp.I18n;
import func.RuleDownloadTask;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class YamlUtil {
    // Rules.yaml 顶层 key：规则列表
    public static final String LOAD_LIST_KEY = "Load_List";
    // Rules.yaml 顶层 key：域名白名单（被动扫描），值为字符串
    public static final String HOST_FILTER_KEY = "filter_host";
    // Rules.yaml 顶层 key：域名黑名单（被动扫描），值为逗号分隔字符串
    public static final String BLACK_HOST_KEY = "black_host";

    private static final String DEFAULT_HOST_FILTER = "*";
    private static final String DEFAULT_BLACK_HOST = "";

    private static final AtomicBoolean RULE_DOWNLOAD_RUNNING = new AtomicBoolean(false);
    private static final ExecutorService RULE_DOWNLOAD_EXECUTOR = Executors.newSingleThreadExecutor(new ThreadFactory() {
        private final AtomicInteger index = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "RouteVulScan-rule-download-" + index.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        }
    });

    public static Map<String, Object> defaultYamlData() {
        Map<String, Object> data = new HashMap<String, Object>();
        data.put(LOAD_LIST_KEY, new ArrayList<Map<String, Object>>());
        data.put(HOST_FILTER_KEY, DEFAULT_HOST_FILTER);
        data.put(BLACK_HOST_KEY, DEFAULT_BLACK_HOST);
        return data;
    }

    /**
     * 在已有 map 基础上补齐 Load_List / host key 的默认值与类型，
     * 确保 host key 一定存在且为字符串、Load_List 一定存在且为 List。
     */
    @SuppressWarnings("unchecked")
    private static void ensureKnownKeys(Map<String, Object> data) {
        if (!(data.get(LOAD_LIST_KEY) instanceof List)) {
            data.put(LOAD_LIST_KEY, new ArrayList<Map<String, Object>>());
        }
        if (!(data.get(HOST_FILTER_KEY) instanceof String)) {
            data.put(HOST_FILTER_KEY, DEFAULT_HOST_FILTER);
        }
        if (!(data.get(BLACK_HOST_KEY) instanceof String)) {
            data.put(BLACK_HOST_KEY, DEFAULT_BLACK_HOST);
        }
    }

    /**
     * 从已读取的 yaml map 中读白名单（filter_host），缺失返回 fallback。
     */
    public static String readHostFilter(Map<String, Object> data, String fallback) {
        if (data == null) {
            return fallback;
        }
        Object v = data.get(HOST_FILTER_KEY);
        if (v instanceof String && !((String) v).trim().isEmpty()) {
            return ((String) v).trim();
        }
        return fallback;
    }

    /**
     * 从已读取的 yaml map 中读黑名单（black_host）原始串，缺失返回 fallback。
     */
    public static String readBlackHost(Map<String, Object> data, String fallback) {
        if (data == null) {
            return fallback;
        }
        Object v = data.get(BLACK_HOST_KEY);
        if (v instanceof String) {
            return (String) v;
        }
        return fallback;
    }

    /**
     * 把白名单与黑名单写回 Rules.yaml：读全量 → put 两个 host key → 写回全量。
     * 这样可保留 Load_List 不变。
     */
    public static void writeHostLists(String filePath, String filterHost, String blackHost) {
        Map<String, Object> data = readYaml(filePath);
        data.put(HOST_FILTER_KEY, filterHost == null ? DEFAULT_HOST_FILTER : filterHost);
        data.put(BLACK_HOST_KEY, blackHost == null ? DEFAULT_BLACK_HOST : blackHost);
        writeYaml(data, filePath);
    }

    public static void init_Yaml(BurpExtender burp, JPanel one) {
        if (!RULE_DOWNLOAD_RUNNING.compareAndSet(false, true)) {
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                    one,
                    burp.t("rules.updateInProgress"),
                    burp.t("dialog.info"),
                    JOptionPane.INFORMATION_MESSAGE
            ));
            return;
        }
        RULE_DOWNLOAD_EXECUTOR.submit(new RuleDownloadTask(burp, one, RULE_DOWNLOAD_RUNNING));
    }

    public static void shutdownRuleDownloadExecutor() {
        RULE_DOWNLOAD_EXECUTOR.shutdownNow();
    }

    public static Map<String, Object> readYaml(String file_path) {
        File file = new File(file_path);
        if (!file.exists()) {
            Map<String, Object> data = defaultYamlData();
            writeYaml(data, file_path);
            return data;
        }
        try (InputStream inputStream = new FileInputStream(file)) {
            Yaml yaml = new Yaml();
            Object loaded = yaml.load(inputStream);
            Map<String, Object> data;
            if (loaded instanceof Map) {
                // 直接保留文件里的所有顶层 key，再补齐已知 key 的默认值/类型。
                data = (Map<String, Object>) loaded;
            } else {
                data = defaultYamlData();
            }
            ensureKnownKeys(data);
            return data;
        } catch (Throwable e) {
            BurpExtender.logStaticError(I18n.t("log.readYamlFailed", file_path), e);
            return defaultYamlData();
        }
    }

    public static void writeYaml(Map<String, Object> data, String filePath) {
        Yaml yaml = new Yaml();
        Map<String, Object> saveData = data != null ? data : defaultYamlData();
        ensureKnownKeys(saveData);
        // 用 LinkedHashMap 按固定顺序重组，保证输出稳定（filter_host、black_host 在前，Load_List 在后）。
        // 这样无论 saveData 来自 load（旧文件可能 host key 在末尾）还是 HashMap，文件结构都一致。
        Map<String, Object> ordered = new LinkedHashMap<String, Object>();
        ordered.put(HOST_FILTER_KEY, saveData.get(HOST_FILTER_KEY));
        ordered.put(BLACK_HOST_KEY, saveData.get(BLACK_HOST_KEY));
        ordered.put(LOAD_LIST_KEY, saveData.get(LOAD_LIST_KEY));
        for (String key : saveData.keySet()) {
            if (!ordered.containsKey(key)) {
                ordered.put(key, saveData.get(key));
            }
        }
        try (PrintWriter writer = new PrintWriter(new File(filePath))) {
            yaml.dump(ordered, writer);
        } catch (FileNotFoundException e) {
            BurpExtender.logStaticError(I18n.t("log.writeYamlFailed", filePath), e);
        }
    }

    public static void removeYaml(String id, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get(LOAD_LIST_KEY);
        ArrayList<Map<String, Object>> List2 = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> zidian : List1) {
            if (!zidian.get("id").toString().equals(id)) {
                List2.add(zidian);
            }
        }
        // 读全量后只替换 Load_List，保留 filter_host/black_host 等顶层 key。
        Map<String, Object> save = YamlUtil.readYaml(filePath);
        save.put(LOAD_LIST_KEY, List2);
        YamlUtil.writeYaml(save, filePath);
    }

    public static void updateYaml(Map<String, Object> up, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get(LOAD_LIST_KEY);
        List<Map<String, Object>> List2 = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id").toString().equals(up.get("id").toString())) {
                List2.add(up);
            } else {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = YamlUtil.readYaml(filePath);
        save.put(LOAD_LIST_KEY, List2);
        YamlUtil.writeYaml(save, filePath);

    }

    public static void addYaml(Map<String, Object> add, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get(LOAD_LIST_KEY);
        int panduan = 0;
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id").toString().equals(add.get("id").toString())) {
                panduan += 1;
            }
        }
        if (panduan == 0) {
            Map<String, Object> save = YamlUtil.readYaml(filePath);
            List1.add(add);
            save.put(LOAD_LIST_KEY, List1);
            YamlUtil.writeYaml(save, filePath);
        }

    }

    public static Map<String, Object> readStrYaml(String str){
        Yaml yaml = new Yaml();
        Object loaded = yaml.load(str);
        Map<String, Object> data;
        if (loaded instanceof Map) {
            data = (Map<String, Object>) loaded;
        } else {
            data = defaultYamlData();
        }
        ensureKnownKeys(data);
        return data;
    }


    public static void MergerUpdateYamlFunc(Map<String, Object> newYaml){
        Map<String, Object> oldYaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        List<Map<String, Object>> oldYamlList = (List<Map<String, Object>>)oldYaml.get(LOAD_LIST_KEY);
        List<Map<String, Object>> newYamlList = (List<Map<String, Object>>)newYaml.get(LOAD_LIST_KEY);
        for (Map<String, Object> i : newYamlList){
            if (!YamlUtil.inYamlList(oldYamlList,i)){
                int id = 0;
                for (Map<String, Object> zidian : (List<Map<String, Object>>)YamlUtil.readYaml(BurpExtender.Yaml_Path).get(LOAD_LIST_KEY)) {
                    Object idVal = zidian.get("id");
                    int curId = idVal instanceof Number ? ((Number) idVal).intValue() : Integer.parseInt(String.valueOf(idVal));
                    if (curId > id) {
                        id = curId;
                    }
                }
                id += 1;
                i.remove("id");
                i.put("id",id);
                YamlUtil.addYaml(i,BurpExtender.Yaml_Path);
            }
        }
        // 合并后读全量（含 host key），保留 filter_host/black_host。
        Map<String, Object> save = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        save.put(LOAD_LIST_KEY, save.get(LOAD_LIST_KEY));

        // 云端若"显式"提供 filter_host/black_host 才覆盖本地。
        // 注意：readStrYaml 会用 ensureKnownKeys 给云端补默认值(* / "")，
        // 所以不能仅靠 readHostFilter!=null 判断，需要排除默认值，避免用云端默认值覆盖本地自定义值。
        String cloudFilter = readHostFilter(newYaml, DEFAULT_HOST_FILTER);
        if (!DEFAULT_HOST_FILTER.equals(cloudFilter)) {
            save.put(HOST_FILTER_KEY, cloudFilter);
        }
        String cloudBlack = readBlackHost(newYaml, DEFAULT_BLACK_HOST);
        if (!DEFAULT_BLACK_HOST.equals(cloudBlack)) {
            save.put(BLACK_HOST_KEY, cloudBlack);
        }

        YamlUtil.writeYaml(save, BurpExtender.Yaml_Path);
    }


    public static boolean inYamlList(List<Map<String, Object>> mapList,Map<String, Object> oneMap){
        for (Map<String, Object> i : mapList){
            if (YamlUtil.ifmapEqual(i,oneMap)){
                return true;
            }
        }
        return false;

    }

    /**
     * 判定两条规则的业务内容是否相同（忽略 loaded / id / type）。
     * 用 Objects.equals 做 null 安全比较，并双向往返检查两侧 keySet，
     * 确保任一侧缺失字段或值为 null 时都能正确判定，避免 NPE 与误判。
     */
    public static boolean ifmapEqual(Map<String, Object> i, Map<String, Object> oneMap){
        return fieldsEqual(i, oneMap) && fieldsEqual(oneMap, i);
    }

    private static boolean fieldsEqual(Map<String, Object> src, Map<String, Object> dst){
        for (String key : src.keySet()){
            if (!key.equals("loaded") && !key.equals("id") && !key.equals("type")){
                if (!java.util.Objects.equals(src.get(key), dst.get(key))){
                    return false;
                }
            }
        }
        return true;
    }



}
