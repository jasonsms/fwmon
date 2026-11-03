# fwmon — OpenWrt 入站(L4)监控设计方案

> 与 fn-knock（L7 应用层）互补的防火墙 / conntrack 入站监控
>
> **状态**：设计稿 v0.1 · 待确认后进入实现
> **目标平台**：ImmortalWrt（OpenWrt 24.10 系）· qualcommax/ipq60xx · ARMv8 v8l ×4 · 2GB RAM + 8GB eMMC
> **固件**：ImmortalWRT SNAPSHOT r0-c674a26 / LuCI Master 26.089.10518~2c5b153 / 内核 6.12.79

---

## 0. 摘要

在路由器上做一个**轻量、可打包为 IPK 的入站连接(L4/网络层)监控**：采集 conntrack 新建入站连接，按源 IP 聚合，检测扫描 / 泛洪 / 暴破 / 突增，写入"RAM 存原始、eMMC 存聚合"的分层存储，并提供 LuCI 面板可视化。

它**不替代** fn-knock，而是补齐 fn-knock 看不到的一段：

| 维度 | fn-knock（L7） | fwmon（L4，本项目） |
|---|---|---|
| 视角 | 应用层 HTTP 请求 | 网络层连接（conntrack NEW） |
| 覆盖 | 穿过反代的请求 / WAF / 认证 | **所有入站新建连接尝试**（含未到 HTTP 的） |
| 看不到 | 泛洪、半开、非 HTTP、被丢弃探测 | 请求内容、Web 攻击、登录语义 |
| 数据源 | 自身网关日志 | conntrack 事件 |
| 作用 | 保护 + 审计暴露服务 | 网络层"谁在敲门 / 打我"早期告警 |

一句话：**fn-knock 守"进门之后"，fwmon 看"门口和门本身"**，二者互补。

---

## 1. 背景 · 目标 · 约束

### 1.1 为什么需要 L4 层

用户环境（关键事实）：
- 移动宽带，**无公网 IPv4**（CGNAT）→ IPv4 入站几乎为 0。
- 光猫默认阻断所有 IPv6 forward，仅放行 **一个 TCP 端口**（`ip6tables -D FORWARD -p tcp --dport XXXX -j ACCEPT`）。
- OpenWrt 仅一条"入站 IPv6 / TCP / wan→此设备 / 端口 XXXX / 接受"。
- 该端口跑 **fn-knock 反向代理网关**，域名经 ACME/子域反代 LuCI、NAS 等内网服务。

因此入站面很窄，但暴露的是 **LuCI / NAS 等高价值目标**。fn-knock 的"请求分析"只记 HTTP 层；**连接层（SYN 泛洪、半开、非 HTTP、被丢弃探测）是它的结构性盲区**——这正是 fwmon 要补的一段。

### 1.2 目标

1. 采集**外部主动发起的入站新建连接**（conntrack `NEW`，WAN→本机/内网）。
2. 按**源 IP** 聚合（谁、打哪个口、多凶、何时起止），并保留每小时趋势。
3. 检测 **端口扫描 / 连接泛洪 / 暴力破解 / 突增 / 丢弃异常 / 惯犯**，分级告警。
4. **最小记录 + 分层存储**：RAM 存原始，eMMC 只存聚合；严格容量上限，最小化 eMMC 磨损。
5. 提供 **LuCI 面板**（概览 / 攻击者 IP / 事件告警 / 设置）。
6. 打包为 **OpenWrt IPK**，procd 服务化，UCI 配置，自包含、非侵入。

### 1.3 非目标（明确不做）

- 不做 L7 内容检测 / Web 攻击识别（归 fn-knock）。
- 不做 IDS 签名库、深度包检测（DPI）。
- 不修改 fn-knock 本身、不接管其反代。
- 不做历史数据的大数据/云端上报（本地自治）。
- 不对下载回程（ESTABLISHED/RELATED）记账。

### 1.4 约束

- **存储**：2GB RAM（tmpfs `/tmp` 共享）+ 8GB eMMC；写入要省，防磨损。
- **算力**：ARMv8 1.3GHz×4，采集/检测必须轻量、有界内存。
- **非侵入**：不改动 fw4/防火墙规则语义，不依赖额外防火墙包（与 fn-knock 的打包约定一致）。
- **可丢弃**：大流量攻击时，宁可丢弃原始样本并计数，也不能撑爆 RAM 或拖垮设备。

---

## 2. 架构总览

### 2.1 组件图

```
                外部扫描 / 攻击（L3/L4）
                          │
                          ▼
        ┌──── 光猫（仅放行 TCP:XXXX）────┐
        └───────────────┬────────────────┘
                        ▼
        ┌──── OpenWrt / ImmortalWrt ─────────────────────┐
        │  conntrack（kmod-nf-conntrack，内核态）          │
        │      │  NEW 入站连接事件                          │
        │      ▼                                          │
        │  ┌────────────  fwmon  ─────────────────────┐   │
        │  │ ① 采集：解析 conntrack 事件流               │   │
        │  │        过滤 = NEW 且 入站                  │   │
        │  │ ② 聚合：内存每源IP/端口/小时（有界）         │   │
        │  │ ③ 检测：扫描/泛洪/暴破/突增 → 告警          │   │
        │  │ ④ 存储：/tmp 原始+当日  ──每日──▶ eMMC 汇总 │   │
        │  │ ⑤ API：127.0.0.1 / unix socket（仅本机）    │   │
        │  └───────────────┬─────────────────────────-┘   │
        │        ┌─────────┴─────────┐                    │
        │        ▼                   ▼                    │
        │  LuCI 面板           (可选) 拉黑 nft 集合        │
        │  luci-app-fwmon      fwmon_block                │
        └─────────────────────────────────────────────────┘
                        │
        互补：fn-knock（L7：请求日志 / WAF / 认证）← 网关 :XXXX
```

### 2.2 数据流

`conntrack 事件` → `过滤(NEW+入站)` → `内存聚合` → `{检测引擎, 分层存储}` → `本机 API` → `LuCI`。
告警可选触发 `拉黑 / 通知`。

### 2.3 与 fn-knock 的边界

- **采集互不干扰**：fwmon 只读 conntrack，不碰 fn-knock；fn-knock 不感知 fwmon。
- **响应可联动**：fwmon 命中的攻击 IP，可选同步进 fn-knock 通用黑名单（L7 侧再挡一次）或本地 nft 集合（L4 侧挡）。
- **面板互不依赖**：LuCI 面板独立；fn-knock 面板独立。

---

## 3. 采集规则（Capture）

### 3.1 数据源选型

| 方案 | 描述 | 优点 | 缺点 | 结论 |
|---|---|---|---|---|
| **A. conntrack 事件流**（推荐） | 读 `conntrack -E`（conntrack-tools）事件，解析 NEW | 非侵入、连接级、无需改防火墙、依赖小 | 处置(accept/drop)需推断 | ✅ 主选 |
| B. nftables `ct state new` + 日志 | 在 input/forward 加 `ct state new limit ... log`，用 ulogd/logread 收 | 处置精确(verdict) | 侵入(改规则)、逐连接限速日志、依赖 ulogd | 备选 |
| C. 原生 ctnetlink | 自己订阅 netlink conntrack 组 | 最轻、零依赖 | 代码量大 | 进阶 |

**选定：方案 A（`conntrack -E`）**。理由：只读、不改防火墙（满足"非侵入 + 不依赖防火墙包"）、连接级、依赖仅 `conntrack-tools`（+ 内核 `kmod-nf-conntrack`，base 自带）。处置 accept/drop 用"是否见到回包 / 目标是否为放行端口"近似推断，够用；若日后要精确 verdict 再切方案 B。

### 3.2 过滤规则（核心）

只保留同时满足：
1. 事件类型 = **`NEW`**（排除 `UPDATE`/`DESTROY`，从而排除下载回程 ESTABLISHED/RELATED）。
2. 方向 = **入站**：原始方向 tuple 的 `dst` 是本机(WAN/LAN 地址)或内网，且 `src` 是外部。
3. 协议归一：`tcp / udp / icmpv6 / other`。

**排除**：`ESTABLISHED`、`RELATED`（内网主动下载的回程）——这正是"下载不算入站"的落地。仅记"外部主动发起的新建连接"。

### 3.3 采集实现（方案 A）

- procd 启动 `fwmon`，后者 `fork/exec`：`conntrack -E -n`（数字输出，省 DNS 反解），逐行解析：
  - 事件标记 `[NEW]` → 保留；否则跳过。
  - 解析原始方向 `src=`、`dport=`、协议（首字段 tcp/udp/icmpv6）。
  - 方向判据：`daddr` 属于本机地址集（WAN/LAN 接口地址）→ 入站。
- 解析后立即投递到聚合器；不落任何逐包日志。

### 3.4 采样 · 限速 · 丢弃计数

- **有界内存**：每源 IP 映射上限（默认 20,000，LRU 淘汰），每 IP 记录端口上限（默认 top 32）。
- **处理限速**：单源每秒事件超阈值时合并计数（不逐条入库），防止极端洪泛拖垮。
- **原始样本上限**：`/tmp` 原始样本文件封顶（默认 30MB），超出丢弃并 `dropped++` 计数（面板可见）。
- 一切超限都**丢弃 + 计数**，绝不阻塞、不撑爆 RAM。

---

## 4. 事件 Schema

字段遵循"最小记录"：仅 `时间 / 源IP / 目标端口 / 协议 / 处置` 为核心；其余为聚合派生。

### 4.1 原始事件（raw，仅存 `/tmp`，可选）

JSONL，一行一事件（约 60–70 字节）：

```json
{"t":1767999999,"src":"2409:8a00::1","dport":443,"proto":"tcp","v":1}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `t` | u32 | Unix 秒时间戳 |
| `src` | string | 源 IP（IPv6/IPv4） |
| `dport` | u16 | 目标端口（icmp 为 0） |
| `proto` | enum | `tcp/udp/icmpv6/other` |
| `v` | u8 | 处置推断：`1`=放行(accept) `0`=丢弃(drop) |

> `state`/`iface` 省略（本方案恒为 NEW、恒为 wan 入站）。`dst_ip` 省略（基本恒定为放行口/本机）。

### 4.2 每源 IP 聚合（per-IP，eMMC 持久化核心）

对应 fn-knock `GatewayLogIpGroupData` 思路，攻击者画像：

```json
{
  "src": "2409:8a00::1",
  "events": 1342,
  "accept": 1200, "drop": 142,
  "first_seen": "2026-11-03T00:12:03+08:00",
  "last_seen":  "2026-11-03T02:41:19+08:00",
  "top_ports": [ {"dport":443,"n":1200}, {"dport":22,"n":142} ],
  "proto": {"tcp":1342},
  "hourly": [0,0,...,1200,142,...,0],
  "flags": {"scan":0, "flood":1, "bruteforce":1, "repeat":0}
}
```

### 4.3 全局每小时直方图（hourly，趋势）

```json
{ "date":"2026-11-03", "tz":"Asia/Shanghai",
  "new_total":[...24...], "new_drop":[...24...], "unique_src":[...24...] }
```

### 4.4 告警事件（alert）

```json
{ "ts":1767999999, "type":"flood", "severity":"high",
  "src":"2409:8a00::1", "metric":"new_conn_per_min", "value":412, "threshold":300,
  "window":"2m", "detail":"单源连接泛洪" }
```

`type ∈ scan | flood | bruteforce | spike | drop_anomaly | repeat`；`severity ∈ info | warn | high | critical`。

### 4.5 存储格式

- `/tmp`：`raw-today.jsonl`（封顶）+ `agg-today.json`（当日每源聚合）+ `hourly-today.json`。
- eMMC：每日 `fwmon-YYYY-MM-DD.json.zst`（每源聚合 + 小时直方图 + 告警摘要），压缩。

---

## 5. 聚合与存储（Aggregation & Storage）

### 5.1 内存聚合（有界）

- 结构：`HashMap<src → IpAgg>` + LRU（上限 20k），`HashMap<dport → count>`（每 IP top 32）。
- 计数字段：`events / accept / drop / first_seen / last_seen / hourly[24] / proto / flags`。
- 增量更新 O(1)，定时（默认 60s）把快照序列化到 `/tmp`（当日聚合）。

### 5.2 分层存储（关键：省 eMMC、防磨损）

| 层 | 位置 | 介质 | 内容 | 生命周期 |
|---|---|---|---|---|
| 原始样本 | `/tmp/fwmon/raw-today.jsonl` | RAM | 逐事件样本（封顶 30MB） | 当日，重启即失 |
| 当日聚合 | `/tmp/fwmon/agg-today.json` | RAM | 每源 IP 聚合 + 小时 | 当日，滚动刷新 |
| 历史汇总 | eMMC `/overlay/…/fwmon/*.json.zst` | eMMC | 每日压缩聚合 | 保留 N 天（默认 90） |

> **只把"聚合结果"写入 eMMC**，绝不把原始大日志搬到 eMMC —— 这是磨损最小化的核心。

### 5.3 每日转存（rollup）

- 触发：每日本地 `00:05`（或 size 阈值）+ 关机/停止时。
- 动作：读当日内存/`/tmp` 聚合 → 压缩(zstd) → 写 `eMMC/fwmon/fwmon-<date>.json.zst` → 清理 `/tmp` 当日原始 → 保留窗口外的旧文件删除。
- 失败兜底：写临时文件 + 原子 rename；失败保留 `/tmp` 当日数据下次重试。

### 5.4 容量控制与磨损最小化

- 原始 `/tmp` 封顶 30MB（超限丢弃+计数）。
- 内存聚合上限 20k IP / 32 端口（LRU）。
- eMMC 仅每日 1 个小压缩文件，默认保留 90 天（可调 30–365）。
- 无逐包写盘；写盘集中在每日一次 rollup。日写入量 ≈ 数十 KB，磨损可忽略。

### 5.5 保留与清理

- `retention_days`（UCI，默认 90）：启动时 + 每日 rollup 后删除窗口外文件。
- `max_total_mb`（UCI，默认 200MB）：总量兜底，超过按日期从旧到新删。

---

## 6. 检测逻辑（Detection）

### 6.1 威胁模型

结合窄暴露面（单 TCP 端口 + 无公网 IPv4），主要威胁：
1. **针对放行端口(fn-knock)的 L4 连接泛洪 / 半开**（fn-knock 看不到，最危险）。
2. **端口扫描 / 探测**（少量打到 OpenWrt，多数被光猫丢弃）。
3. **针对暴露服务的暴力连接**（反复建连，配合 fn-knock 侧登录暴破）。
4. **流量突增 / 异常**（可能是攻击前兆或正在进行的攻击）。
5. **惯犯**（跨日重复出现的攻击源）。

### 6.2 规则（可在 UCI 调阈值）

| # | 类型 | 触发条件（默认） | 级别 | 说明 |
|---|---|---|---|---|
| R1 | `scan` | 单源 5 分钟内 ≥ **15** 个不同 `dport` | warn | 端口扫描 |
| R2 | `flood` | 单源 ≥ **300** NEW/分钟 持续 ≥ 2 分钟 | high | 连接泛洪（L4 盲区） |
| R3 | `bruteforce` | 单源 2 分钟内 ≥ **60** 次连**放行端口** | high | 暴破 fn-knock 入口 |
| R4 | `spike` | 全局 NEW/分钟 > 当小时基线中位数 × **5** | warn | 流量突增 |
| R5 | `drop_anomaly` | 被丢弃 NEW/分钟 > 基线 × **3** | info | 探测/扫描增多 |
| R6 | `repeat` | 同源 IP 事件出现在 ≥ **3** 个不同日期 | warn | 惯犯（跨日） |

- **基线**：滚动窗口（如近 7 天同小时中位数）。
- **去抖**：同一 `type+src` 在冷却期（默认 10 分钟）内只告警一次，避免刷屏。

### 6.3 严重级别

`info` < `warn` < `high` < `critical`（保留给未来：全局限速触发）。映射到 LuCI 颜色与通知级别。

### 6.4 响应动作

| 动作 | 默认 | 说明 |
|---|---|---|
| 记录 + 面板展示 | ✅ 始终 | 告警入事件列表 |
| **微信 PushPlus 通知** | 可选 | POST `http://www.pushplus.plus/send`，UCI 配 `pushplus_token`；面板设置页有 token 输入框 |
| 自动拉黑（nft 集合 `fwmon_block`） | ❌ 默认关 | 开启后对 high+ 源 REJECT，时长可配（默认 1h），到期解除 |
| 同步 fn-knock 通用黑名单 | ❌ 默认关 | 调 fn-knock 本地接口把源 IP 加入其黑名单（L7 再挡） |

> 自动拉黑**默认关闭**（避免误封、避免与现有防火墙策略冲突）；开启需用户显式确认。
> PushPlus 通知只发告警（按级别可配），token 仅存 UCI、仅本机使用。

---

## 7. LuCI 面板（luci-app-fwmon）

### 7.1 菜单与 ACL

- 菜单：`网络 → 入站监控`（`usr/share/luci/menu.d/luci-app-fwmon.json`）。
- ACL（`usr/share/rpcd/acl.d/luci-app-fwmon.json`）：仅开放**读 fwmon API** + 少量动作（拉黑/解除、刷新、改本应用设置）。**不给通用防火墙写权限**（与 fn-knock 的保守 ACL 一致）。

### 7.2 页面

仿 fn-knock"请求分析"三段式 + 设置：

1. **概览 Dashboard**
   - 指标卡：今日新建入站数、独立攻击 IP、丢弃率、放行端口命中数、当前告警数。
   - 趋势图：每小时 NEW（放行/丢弃/独立 IP）折线。
   - Top 攻击者摘要、活跃告警。

2. **攻击者 IP（Per-IP）**
   - 列表（对应 per-IP schema）：源 IP、事件数、放行/丢弃、Top 端口、首见/末见、flags。
   - 排序：事件数 / 最近 / 丢弃 / 端口数；下钻看逐小时 + 端口分布。
   - 动作：拉黑 / 解除（可选）、导出。

3. **事件告警（Alerts）**
   - 列表：时间、类型、级别、源 IP、指标值/阈值、详情；按级别/类型/时间筛。

4. **设置（Settings）**
   - 启用开关；容量（原始上限、内存 IP 上限、保留天数、总量上限）。
   - 检测阈值（R1–R6 各参数）；放行端口；通知开关；自动拉黑开关+时长。

### 7.3 API 契约（fwmon → LuCI，仅本机）

`GET  /api/summary?date=` → 今日指标 + 小时序列
`GET  /api/ips?sort=&limit=&date=` → 每源列表
`GET  /api/ips/:src` → 单源详情（逐小时 + 端口）
`GET  /api/alerts?limit=&since=&type=&severity=` → 告警
`GET/PUT /api/config` → 读/写设置（UCI 同步）
`POST /api/ips/:src/block` · `POST /api/ips/:src/unblock` → 拉黑（可选）
`GET  /api/health` → 运行态、dropped、队列深度、存储用量

- 传输：`127.0.0.1:<port>`（默认 8099）或 unix socket；**只监听本机**，不经公网。
- 标准 JSON 信封（`{code, data, message}`），便于 LuCI JS 消费。

### 7.4 前端技术

现代 LuCI JS：`www/luci-static/resources/view/fwmon/*.js`（概览/攻击者/告警/设置四个 view），复用 LuCI 自带 chart/table 组件；不引入重型框架。

---

## 8. IPK 目录结构

仿 fn-knock `deploy/openwrt` 模板（tar 型 IPK）：

```
fwmon/
├── CONTROL/
│   ├── control                 # 包元信息（Package/Version/Depends/Architecture）
│   ├── postinst                # 启用服务、初始化 UCI、（可选）注册 nft 集合
│   ├── prerm                   # 停服务、清理
│   └── postrm                  # 删 nft 集合/残留、（可选）保留数据
├── etc/
│   ├── config/fwmon            # UCI 配置
│   ├── init.d/fwmon            # procd 服务脚本
│   └── uci-defaults/           # 首次启动默认（可选）
├── usr/
│   ├── sbin/fwmon              # 主守护进程（静态/轻依赖）
│   ├── lib/fwmon/              # 辅助脚本：nft 集合管理、每日 rollup、清理
│   ├── share/
│   │   ├── luci/menu.d/luci-app-fwmon.json
│   │   └── rpcd/acl.d/luci-app-fwmon.json
└── www/luci-static/resources/
    ├── fwmon/fwmon.png
    └── view/fwmon/             # LuCI JS 页面
        ├── overview.js
        ├── attackers.js
        ├── alerts.js
        └── settings.js
```

### 8.1 UCI 配置 schema（`/etc/config/fwmon`）

```
config fwmon 'main'
    option enabled '1'
    option listen_port '8099'          # 本机 API
    option exposed_port '443'          # 放行端口（fn-knock 网关）
    option raw_max_mb '30'
    option agg_max_ips '20000'
    option agg_max_ports '32'
    option retention_days '90'
    option max_total_mb '200'
    option flush_interval '60'
    option auto_block '0'
    option block_ttl '3600'
    option notify '0'
    option pushplus_token ''
    option notify_min_severity 'warn'

config detect 'thresholds'
    option scan_ports '15'
    option scan_window '300'
    option flood_per_min '300'
    option flood_sustain '120'
    option bruteforce_count '60'
    option bruteforce_window '120'
    option spike_factor '5'
    option drop_factor '3'
    option repeat_days '3'
    option cooldown '600'
```

### 8.2 依赖（`control`）

- `Depends: libc, conntrack-tools, zstd, luci-base`
- 内核：`kmod-nf-conntrack`（base 自带，不强依赖）。
- **不依赖 iptables/nftables/firewall 包**（沿用 fn-knock 的打包纪律，避免与 fw4 冲突）。
- `Architecture`：按目标给 `aarch64_cortex-a53` / `aarch64_generic` 等（构建矩阵见 8.4）。

### 8.3 init.d / procd

- `procd` 服务：`respawn`、`stdout/stderr` 接日志、依赖 `firewall`/`network` 起后启动。
- 启动：加载 UCI → 起 `fwmon` 守护（内部再起 `conntrack -E` 子进程）→ 注册每日 rollup 计时。
- 停止：flush 当日聚合 → 优雅停 → 清理子进程。
- （可选）`fwmon_block` nft 集合的建立/销毁放 `postinst/postrm` + helper，不污染 fw4 规则。

### 8.4 构建与打包

- 交叉编译 `fwmon` 二进制（目标 `aarch64`，静态或 musl），LuCI/配置/脚本按目录就位。
- 打包：tar 型 IPK（`data.tar.gz` + `control.tar.gz` + `debian-binary`），可参考 fn-knock `scripts/build-openwrt-ipk.sh` 的 tar 归一化（`--owner=0`、排序、拒绝防火墙包依赖）。
- 产物矩阵：`aarch64_cortex-a53`（你的 ipq60xx 适用）、`aarch64_generic`、`x86_64`（便于测试）。
- 校验：生成 `sha256sums`；本地 `opkg install` 验证后交付。

---

## 9. 实现计划（里程碑）

| 阶段 | 内容 | 交付 |
|---|---|---|
| M1 采集+聚合 | `conntrack -E` 解析、NEW 入站过滤、内存每源聚合、`/tmp` 落盘 | 能出每源 IP 基础统计 |
| M2 存储+rollup | 分层存储、每日 zstd 转存 eMMC、容量上限、清理 | 磨损受控、可持久 |
| M3 检测引擎 | R1–R6 规则、基线、去抖、告警事件 | 能报警 |
| M4 API+面板 | 本机 JSON API、LuCI 四页、ACL | 可视化 + 设置 |
| M5 响应+打包 | 拉黑/通知（可选）、IPK、init.d、UCI、构建脚本 | 可安装 .ipk |
| M6 联调+验收 | 与 fn-knock 并跑、真实流量/模拟攻击验证、阈值调优 | 上路由器验收 |

---

## 10. 已确认决策（v0.2）

| 项 | 决定 |
|---|---|
| 包名 / 面板 | `fwmon` + `luci-app-fwmon`；面板名 **"入站监控"** |
| 采集方案 | **conntrack -E**（方案 A，非侵入） |
| 放行端口 | 自定义（UCI `exposed_port`，面板设置页输入） |
| 自动拉黑 | **默认关** |
| 保留天数 | **默认 90 天** |
| 告警通知 | **微信 PushPlus**，UCI/面板设 token |
| 二进制语言 | **Rust**（静态 musl，交叉编译到 aarch64） |

实现计划见第 9 节 M1→M6。

---
_已按上述决策进入实现。_
