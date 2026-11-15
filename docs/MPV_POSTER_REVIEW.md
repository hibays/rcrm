# Rust review：libmpv 海报（第二版）

日期: 2026-11-16（第二版；同日第一版被本文件取代）
范围（只有 mpv 相关）: `crates/rcrm-flutter-bridge/src/{libmpv.rs,libmpv_poster.rs,poster.rs,webp.rs,lib.rs}`
的 libmpv 路径，以及它的两个 Dart 后端 `services/{poster_libmpv,poster_mpv}.dart` 与
`services/thumbnail_service.dart` 里的排队/暂停部分。

## 0. 结论

上一版把三处“看起来像 bug”的地方按 Must-fix 修了。逐条复核后**三处都不是可复现的
bug，已全部撤回**。现在留在工作区的行为改动只有一项：**被 libmpv 拒绝的选项改用 error
级日志**（mpv 升级时的唯一线索）。其余是解释性注释与一条不变量声明。

复核手段：读实现（含 media_kit_video 2.0.1 源码）、追调用链与参数来源、算可达性。
`cargo miri` 在本机不可用（stable-msvc 无该组件），且 Miri 对 `extern` 调用不透明，
凡涉及别名模型的判断只给出推导依据，不声称“跑过”。

## 1. 逐条复核

| # | 上一版结论 | 复核依据 | 实际结论 | 处置 |
|---|---|---|---|---|
| 1 | `Surface::pointer` 从 `&self` 派生 `*mut` 是 UB | 见 1.1 | **不是 UB** | 撤回，留解释性注释 |
| 2 | `Surface::new` 乘法回绕 → 堆越界 | `generate → target_size → Surface::new` 是唯一链；width ≤ 640、height ≤ 8192 → 21 MB | **不可达** | 撤回，留 `debug_assert` 不变量 |
| 3 | `render` 的 `u32 as c_int` 可能翻负 | 同一约束 | **不可达** | 撤回 |
| 4 | 空 `positions` 会白建 client | Dart `posterSeekPlan` 两个分支都至少返回一个元素 | **不可达** | 撤回 |
| 5 | Dart 海报池可能“有 player 无 controller” | `media_kit_video-2.0.1/…/video_controller.dart:72` 构造器同步、不抛；异步失败走 `:124` 的 `completeError`，消费它的 `:160` 我们已 try/catch | **不会发生** | 撤回 |
| 6 | client API 加 major 上限 | 当前 libmpv 全是 2.x，永不触发；锁 major 会挡住未来版本 | **没必要** | **已按你的意见删除** |

### 1.1 为什么 `Surface::pointer(&self)` 不是 UB

`Vec::as_ptr` 返回的是 `Vec` **内部存着的 buffer 指针**（`self.buf.ptr()`），它不经过
`&[u8]` 切片、也不对堆分配重新打 tag；`&self` 只冻结 `Surface`/`Vec` **结构体自身的
字节**（那个指针值），不冻结它指向的堆分配。libmpv 写的时候，全流程没有任何指向该分配的
`&[u8]` 存活。所以这是“通过结构体里保存的裸指针做内部可变性”，是 FFI 的常规形态。

反例是另一种写法：如果指针来自 `&self.storage[..].as_ptr()`（先造 slice 引用），那才是
从共享引用派生的只读来源，写它就是 UB。代码里没有。

上一版还说过“miri 会红”——这一点也是错的：这次写发生在 libmpv 内部，Miri 对 `extern`
调用不透明，看不到这次写。签名已恢复 `&self`，并留注释说明为什么成立、换成 slice 派生
就不成立（防止下一个人重复这次误判）。

### 1.2 为什么 `Surface::new` 的乘法不可达

`target_size`（`libmpv_poster.rs`）里 `width = max_width.max(1).min(source_width)`，
`max_width` 来自 Dart 常量 `posterWidth = 640`；`height` 被 `clamp(1, MAX_HEIGHT = 8192)`
截断。于是 `len = 640 × 8192 × 4 ≈ 21 MB`：64 位不可能溢出，32 位（armv7）也远低于
`usize::MAX`。改回直接算术，用一条 `debug_assert!` + 注释把这个不变量写在构造函数旁
（release 零成本），不是守卫。

## 2. 现在留在工作区的改动

1. **`libmpv.rs`：被拒选项的日志级别 `log_debug! → log_error!`。**
   mpv 升级最常见的破坏形态是选项改名（`tls-verify`、`http-header-fields`、`keep-open` …），
   而 `mpv_set_option_string` 只返回错误码。这一行是升级后唯一的线索，默认级别可见才叫线索。
2. **注释与不变量**（无行为变化）：`Surface::pointer` 为什么 `&self` 成立；
   `Surface::new` 的尺寸契约 + `debug_assert`；`render` 的 `int[2]` 说明。

## 3. libmpv 海报的并发与异步现状

| 项 | 移动端 | 桌面 | 出处 |
|---|---|---|---|
| 同时生成的海报 | **1** | 4 | `ItemCacheLimit.videoPosterConcurrency` |
| 排队上限 | **24** | **128** | `videoPosterQueueMax`（本版从 50/200 下调；保持在内存 LRU 之下） |
| 内存 LRU | 32 | 512 | `videoPosterMemoryCacheMax` |
| mpv 实例 | Android：每个 job 一个 context，建完即销毁（峰值 1）；iOS：复用池 1 个 Player | 同 Android，峰值 ≤ 4 | `libmpv_poster::generate` / `MpvPoster._ensurePool` |

排队上限为什么必须小于 LRU：被淘汰的等待者会被回答 `null` 且**不会重试**，所以队列比它
喂的那层缓存还深，就等于把槽位花在“结果根本放不下”的请求上。

实测（720×960 竖屏，release）：`load 23–32 ms + seek ≈0 + frame 47–59 + encode 63 ≈ 140 ms/张`。
移动端串行 ≈ 7 张/秒；一屏 20 张约 3 秒，而且是滚动中增量请求。移动端没有跨 job 的
mpv 复用（每张约 25 ms 创建 + 一次线程启动）。

异步模型（只有海报这条链）：

```
VideoPoster.initState → postFrame → ThumbnailService.generatePoster(url)
  ├─ 内存 LRU 命中 → 立即 Future.value
  ├─ ThumbCache 命中 → await 读盘
  ├─ _posterInflight 命中 → 复用同一个 Completer（同 URL 只跑一次）
  └─ 入队 PosterJob（FIFO，上限 24/128，超出淘汰最老等待者 → null）
       → _posterKick: 并发 ≤ 1/4，且未暂停、无 parked job
       → run(): 主 isolate 上的 async 函数
            ├─ libmpv 后端（Android/桌面）：
            │    rcrm_generate_poster_async → Rust std::thread::spawn
            │      → mpv create/loadfile/seek/render/encode
            │      → callback（NativeCallable.listener，回主 isolate 事件循环）
            │    Dart 只 await 一个 Completer，主 isolate 不阻塞，帧不进 Dart
            └─ media_kit 后端（iOS）：
                  池里 1 个 Player.screenshot（原生回调经 media_kit 的 port 回来）
                  seek 完成用 stream.position 的 Future 等，不忙轮询
                  暂停闸门：park → stop → await resume → re-open → unpark
  ← 完成后写内存 LRU + await ThumbCache.write → complete
```

要点：**没有取消机制**（已开始的 job 跑完才回答，排队中的可被淘汰）；**暂停时**队列停止启动，
iOS 的跑中 job 会 park，libmpv 的 job 无法 park（无共享锁）但会跑完；**超时**是 Dart 60 s
兜底 / Rust 40 s 总预算（load 25 s、seek 5 s、frame 3 s 分阶段），正常情况答案总在 Dart
超时前到达，晚到的 Rust 回调自己释放 buffer。

## 4. ffmpeg 9 / mpv 升级前瞻

先给结论：**先坏的会是“播放”，不是海报**。

1. **海报路径**已显式 `tls-verify=no`（`libmpv_poster::options()`）。ffmpeg 9 把
   `tls_verify` 默认值翻成 1 不影响显式设置；风险是 ffmpeg 9 **改名/移除该键**——那时 mpv 仍
   接受 `--tls-verify`（它自己的选项），ffmpeg 忽略未知字典键 → 海报静默变空。升级后对自签
   HTTPS 服务器跑一次 `RCRM_MPV_POSTER_TEST_VIDEO`；兜底顺序：局部 relay →
   `--tls-ca-file` 文件型证书 → `--stream-lavf-o` 传 pin。
2. **播放路径没有任何 tls 选项**（全仓库 grep 只有 `httpHeaders`）：`video_player_screen`、
   `preview_player`、`live_photo`、cast receiver 都是 media_kit 直接开 URL，ffmpeg 9 之后
   自签 HTTPS 的云端模式会**播不动**。现成机制是 `NativePlayer.setProperty('tls-verify','no')`
   （`_resumeAfterTakeBack` 已用该通道），在 `open` 前设置；这等于放弃播放路径的证书校验
   （Dart HTTP 仍 pin），属产品/安全决定，本次只记录。
3. **选项语义/改名**：升级后第一件事 grep `[poster] libmpv rejected option`（第 2 节第 1 项）。
4. **client API 版本**：只保留下限 `REQUIRED_API = 1.28`（render API 自该版本起）。不再锁
   major；下一个 major 会重排 enum 数值、默认禁用事件（`client.h` 的 "Future changes"），
   升级时按 `render.h`/`client.h` 复核一遍事件号与参数号即可。soname 若变成 `libmpv.so.3`，
   需要扩充 `library_names()`。
5. **色彩管线**：`bgr0` 是 ffmpeg 核心格式，风险低；HDR→SDR tone map 默认值变化会让海报
   观感变化，用 MAD/截图对比回归。
6. **SW 渲染性能**：render.h 明说 stride/pointer 不按 64 对齐会退化为整帧拷贝；我们满足，
   升级后若 `frame_ms` 突然变大先查这里。
7. **时序**：“render context 必须在 `loadfile` 前创建”是文档承诺；升级后若出现黑帧/首帧
   错位先复核这一条。
8. **卡死上界**：mpv 默认 `network-timeout=60s`，`loadfile`/`terminate_destroy` 是阻塞调用，
   我们的阶段超时只在阶段之间生效。Dart 超时率变高时先调小 mpv 的 network-timeout。

## 5. 验证

- `cargo fmt --check` 通过；`clippy --all-targets` 在 `libmpv-poster` 与 `mpv-poster`
  两种形态下零 warning；`cargo test -p rcrm-flutter-bridge --features libmpv-poster`
  39 例全绿。
- 真机端到端（720×960）：`load → seek → frame → encode → 640×853 不透明 WebP` 通过
  （debug 下 encode 约 2–3 s 是 debug 编码器；release 实测 63 ms）。
- `flutter analyze lib test`：No issues；`flutter test` 全绿（本次只改了 `videoPosterQueueMax`
  的数值与注释）。

## 6. 未验证

- `cargo miri` 不可用（无 nightly 组件），且 FFI 写对 Miri 不透明，别名模型只有推导依据。
- 未在 Linux/macOS/Android 真机跑真实 libmpv（库发现与 SW 渲染只在 Windows 验过）。
- 4K/HEVC/长 GOP、多路并发下的内存与吞吐未测；`videoPosterConcurrency = 4` 取的是评估
  报告的建议值，不是实测最优。
- 新的排队上限 24/128 只是常量调整，没有压测数据背书；它约束的是“等待中的请求”，
  不改变单张成本。
