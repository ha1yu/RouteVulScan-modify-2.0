# Changelog

## 2026-06-17 / v2.0.6

### 修复

- 修复扫描任务计数泄漏：规则任务触发 `invokeAll` 31 秒超时被取消时，`runningTasks` 只增不减，导致进度面板"运行中任务"数字单调上涨。改为 `noteTaskStarted` / `noteTaskFinished` 严格配对（取消/超时也计 finished）。
- 修复 `StatusCodeProc` 对非法 `state`（`null` / 空 / `abc` / `200-` / `200,xyz` 等）抛 `NumberFormatException` 或 `ArrayIndexOutOfBoundsException`，导致该规则静默失败。改为 null/空校验 + 捕获 `RuntimeException` 返回空集合跳过。
- 修复 `on_off`（被动扫描开关）与 `Carry_head`（携带请求头开关）跨线程读写未声明 `volatile`，导致 EDT 切换后扫描线程可能长期看不到新值（开关"似乎没生效"）。两个字段改为 `volatile`。
- 修复 `UrlRepeat` 用非线程安全 `HashMap` 在并发 HTTP 回调下损坏表结构的风险，改用 `ConcurrentHashMap`；并把去重的 check-then-act 两步合并为原子的 `markIfAbsent`，消除并发重复扫描竞态。
- 修复高 DPI 缩放（>100%）下配置页「保存名单」按钮被遮挡：黑白名单文本框列数由 28 缩至 14，避免单行 `FlowLayout` 总宽超出可视区。
- 移除保存名单底部冗余的灰色反馈 `hostListsStateLabel`（保存已有弹窗反馈，label 重复且过隐蔽），简化 `southPanel` 布局。

### 变更

- 默认黑名单由无效的通配形式 `*.baidu.com,*.qianxin.com` 改为生效的裸域名 `baidu.com,qianxin.com`（黑名单走子串匹配，`*` 不被当通配符，原值实际无法拦截）。

### 新增

- 新增单元测试 `StatusCodeProcTest`（11 例）与 `UrlRepeatTest`（10 例），覆盖非法输入健壮性与去重原子语义。测试用例总计达 **59 个**，全部通过。

## 2026-06-17 / v2.0.5

### 变更

- **黑白名单持久化迁移到 `Rules.yaml`**：白名单与黑名单不再通过 Burp `preferences()` 存储，改用 `Rules.yaml` 顶层 key `filter_host`（白名单）与 `black_host`（黑名单，逗号分隔）。配合规则文件版本化管理，重启 Burp 或重载插件后仍保留。
- **云端下载支持覆盖黑白名单**：云端 `Rules.yaml` 若显式提供非默认值的 `filter_host` / `black_host`，下载合并后会覆盖本地值并即时刷新配置页；云端未提供（或为默认值 `*` / 空）时保留本地值。
- 配置页保存名单后，`Rules.yaml` 顶层结构固定为 `filter_host`、`black_host`、`Load_List` 顺序输出，便于阅读与版本对比。

### 修复

- 修复重复点击「云端下载规则」时的 `NullPointerException`：第二次下载时本地已合并云端规则，`ifmapEqual` 比较到 `method: null` 等字段触发 NPE。改为 `Objects.equals` 做 null 安全比较，并补齐双向往返判等的对称性。
- 修复 `MergerUpdateYamlFunc` 用云端默认值（`*` / 空）误覆盖本地自定义黑白名单的问题：仅当云端值为非默认值时才覆盖。
- 修复 `YamlUtil.readYaml` / `writeYaml` / `readStrYaml` 只 round-trip `Load_List` 一个顶层 key 的问题：通用化后所有顶层 key 均可保留。
- 修复 `removeYaml` / `updateYaml` / `addYaml` 编辑规则时会误删黑白名单的问题：改为「读全量 → 只替换 Load_List → 写回全量」。
- 修复 `MergerUpdateYamlFunc` 中 `(int) zidian.get("id")` 对字符串型 id 的 `ClassCastException`，改用 `Number` 安全转换。
- 修复保存名单后 `filter_host` / `black_host` 被写到 `Rules.yaml` 末尾的问题：`writeYaml` 改用 `LinkedHashMap` 按固定顺序输出。

### 新增

- 新增单元测试 `src/test/java/`，共 **38 个用例**（`YamlUtilTest` 29 + `ParseBlacklistTest` 9），覆盖：YAML 读写 round-trip、host key 处理、编辑规则不丢名单、`ifmapEqual` null 安全与对称性、云端下载合并、黑白名单解析，以及输出顺序回归。

## 2026-06-16 / v2.0.4

### 新增

- 新增 **域名黑名单** 功能：配置页新增一个域名黑名单输入框，多个域名用英文逗号分隔；命中任一条目的 host 不会被被动扫描（子串匹配，忽略大小写）。
- 新增 **保存名单** 按钮：点击后会同时保存白名单与黑名单，立即应用到被动扫描，并通过 Burp `preferences()` 持久化（`routevulscan.whitelist` / `routevulscan.blacklist`），重启 Burp 或重载插件后仍保留。
- 配置页摘要行新增黑名单条目数展示；状态行会显示"已保存并应用"的反馈。

### 变更

- 主机过滤文案从"主机过滤 / Host Filter"调整为"域名白名单 / Domain Whitelist"，与新增的"域名黑名单"对称。
- 黑白名单的生效时机统一为 **点击保存按钮才生效**：编辑输入框文本不再立即改变扫描行为，避免输入过程中实时与持久化状态不一致。
- 被动扫描过滤逻辑改为读取 `volatile` 快照（`activeWhitelist` / `activeBlacklist`），不再在 HTTP 回调线程直接读取 Swing 组件 `Host_txtfield`，消除原有跨线程访问隐患。
- 配置页输入框在插件启动时会回填上次保存的黑白名单值。

### 范围说明

- 黑白名单仅在 **被动扫描** 生效；右键"发送到 RouteVulScan"的主动扫描不受黑白名单限制。
- 黑名单采用子串匹配，注意同形子串可能被误伤（例如填写 `evil.com` 也会命中 `notevil.com`）。

## 2026-05-15 / v2.0.3

### 修复

- 修复 Burp 右键扩展菜单显示为 `Route Vulnerable Scan 2.0.0` 的问题，扩展名统一调整为 `RouteVulScan`。
- 修复右键 `发送到 RouteVulScan 并携带请求头` 行为不符合预期的问题；现在该入口会直接使用当前选中的请求作为扫描模板，不再弹出自定义请求头编辑窗口。
- 修复携带请求头扫描时重新构造请求导致原始业务 header 丢失的问题；现在扫描请求仅替换 URL path，保留原请求中的 `Host`、`Content-Type`、`Content-Length`、认证 header、自定义 header 与其他 request headers。
- 保持规则方法逻辑不变：GET 规则仍发送 GET 请求，POST 规则仍发送 POST 请求，同时复用原始请求头上下文。

## 2026-05-06 / v2.0.2

### 修复

- 修复右键 `发送到 RouteVulScan 并携带请求头` 未真实继承当前请求头的问题。
- 修复右键选择 POST 请求并携带请求头时，扫描请求仍被从零构造为 GET，导致 Logger 中缺失原 POST 方法、请求体与请求头的问题。
- 现在右键携带请求头扫描会以当前选中的请求作为模板，仅替换扫描路径，保留原始方法、body、Cookie、Authorization 与自定义 header。
- 修复右键扫描在 Swing 事件线程同步执行导致 Burp UI 卡住的问题；扫描流程改为后台调度执行。
- 修复被动扫描在 Burp HTTP 回调线程同步执行的问题，避免阻塞代理流量处理。
- 修复云端规则下载完成后在后台线程直接刷新 Swing UI 的问题；规则列表刷新与弹窗统一切回 Swing EDT 执行。
- 修复重复点击 `云端下载规则` 会创建多个下载线程的问题；现在同一时间只允许一个云端规则下载任务运行。
- 云端规则下载改用 Java 17 `HttpClient`，设置连接超时与请求超时，避免网络异常时下载线程长期阻塞。

### 移除

- 移除 `域名扫描` 模块，包括配置页开关、扫描逻辑、域名去重状态与相关中英文文案。
- 移除 `绕过扫描` 模块，包括路径绕过请求变体、配置页开关与相关中英文文案。
- 移除规则文件中的 `Bypass_List` 参数；规则读写与云端合并流程均不再保留该字段。

### 变更

- 规则文件从 `Config_yaml.yaml` 重命名为 `Rules.yaml`，插件启动、规则读取、规则写入与文档说明均改为使用新文件名。
- `更新规则` 按钮重命名为 `云端下载规则`，英文文案为 `Cloud Download Rules`。
- `重新加载规则` 按钮重命名为 `本地重载规则`，英文文案为 `Local Reload Rules`。
- `云端下载规则` 现在从 `https://raw.githubusercontent.com/ha1yu/RouteVulScan-modify-2.0/main/Rules.yaml` 下载规则，并校验 HTTP 状态码与规则内容有效性。
- 扫描调度与规则请求执行分离：新增独立扫描协调线程，规则请求继续使用可配置工作线程池，避免协调任务与规则任务互相阻塞。

## 2026-04-30 / v2.0.1

### 修复

- 修复点击 `重置进度` 后再次访问同一网站不会重新扫描的问题。
- 现在重置会递增扫描代次、重置线程池、清空路径/URL/域名去重状态、清空进度计数，并重新从当前 `Config_yaml.yaml` 加载规则。
- 重置操作不会清空漏洞结果历史；结果历史仍由结果页的 `清除历史` 独立管理。

### 新增

- 新增 English Language Support，配置页可在 `中文` / `English` 之间切换。
- 语言选择通过 Burp Montoya `preferences()` 持久保存，重启 Burp 或重载插件后保持上次选择。
- 新增 `src/main/resources/i18n/messages_zh_CN.properties` 与 `messages_en_US.properties`，集中维护中英文界面文案。
- 调整 Maven Shade 产物命名，后续统一输出 `target/RouteVulScan-V<当前版本>.jar`，例如 `target/RouteVulScan-V2.0.1.jar`。

## 2026-04-06 / v2.0.0

### 修复

- 修复 Burp Suite 2025.10.7 加载插件时报错 `java.lang.IllegalArgumentException: Component cannot be null`。
- 根因是 `UI.Tags` 在构造函数中异步初始化界面，`BurpExtender.initialize()` 在界面根组件尚未创建完成时就调用了 `registerSuiteTab()`。
- 现在改为同步构建 UI 根组件，并在注册前显式校验组件非空，避免初始化时序问题再次出现。

### 构建与兼容性调整

- 保持 Burp 官方主线的 Montoya API，不回退到旧版 Extender API。
- 新增 Maven 构建文件 `pom.xml`，使用 `maven-shade-plugin` 打包。
- 构建目标固定为 JDK 17，适配当前 Burp 2025.x 运行环境。
- 打包产物统一为当时的 `target/RouteVulScan-burp.jar`。
- `montoya-api` 依赖改为 `provided`，避免把 Burp 自带 API 打入插件包。

### 清理

- 删除历史 Gradle 缓存与构建产物目录：`.gradle/`、`build/`。
- 删除 Maven 构建产物目录：`target/`，避免把本地打包结果提交到仓库。
- 删除 macOS 垃圾文件：`.DS_Store`。
- 删除历史 Gradle 构建文件 `build.gradle`，统一只保留 Maven 构建入口。
- 删除不再使用的 `lib/rt.jar` 历史遗留依赖目录。
