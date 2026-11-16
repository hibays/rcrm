# Update report

1. 2022.5.14.10.15.PM.Saturday
	1) 更新默认calibration_amount值为1024→896
	2) 这可能使解密以calibration_amount=1024加密的文件时虽提示成功但实际内容错误致最终酿成无以挽回的损失
	3) 也可能提示解密错误...

2. 2022.5.15.0.15.AM.Sunday
	1) 增加解码检查, 解出来无 b'ftyp' 的话报错

3. 2022.5.21.7.5.PM.Saturday
	1) 报错不再打印directory
	2) 对架构稍作更改

4. 2022.6.3.3.1.PM.Friday
	1) 稍对MOVe/dncode进行优化, 不再设置dat变量等
	2) 增加 xor_ctx.useascii 的setter, 设为False可将加密后数据缩减约18.2%
	3) 添加不可加密时报错

5. 2022.6.5.6.17.AM.Sunday
	1) 修复解码报错问题

6. 2022.7.4.8.39.PM.Monday
	*以下更新不向下兼容* 旧算法请见 `_od_MOVencode`, `_od_MOVdecode`, `_od_main`
	1) 更新编码机制
		① 将密码hash值嵌入文件末尾，增加活动性
		② 将calibration_amount嵌入文件末尾，增加稳固性
	2) 基于以上机制，解码时进行key检查，不通过则报KeyError
	3) 基于以上机制，解码后数据无 b'ftyp' 不再报错
	4) 设MOVencode的calibration_amount参数默认值为1024，MOVdecode不再提供该参数
	5) 更新main函数，增加多用性
	6) 将 xor_ctx.useascii 的值默认设为 False

7. 2022.8.3.12.32.PM.Wednesday
	*以下更新不向下兼容* 旧算法请见 `_od2_MOVencode`, `_od2_MOVdecode`, `_od2_main`
	1) 更改密码算法，增强安全性
	2) 加密核心改用RC4^+加密算法
	3) 稍微优化交互逻辑
	4) 考虑多平台下差异性, 加入Windows适配
		① 文件名ASCII算法从base85改为base58
	5) 将文件名保护嵌入密码算法中, 默认开启
		① 新增参 name_crypt 控制
		② 返回加密后文件名, 未加密返回原名
		③ 文件将更名为其哈希值
	6) 添加复加密验证，若同文件被同一参数加密多次则报 RuntimeError

8. 2022.8.5.11.26.PM.Friday
	1) 优化部分函数的实现

9. 2022.8.20.3.30.PM.Saturday
	1) 在所有版本添加对图片文件的支持

10. 2022.12.3.11.5.PM.Saturday
	1) 将 main 函数 dir 参数的默认值从 `path.dirname(path.dirname(__file__))` 改为 `path.abspath('..')` 以修复 `__file__` 在3.8或pypy中不是绝对路径导致的错误
	2) 添加了人性化的 Seeking Path 提示

11. 2.2023.1.25.9.45.AM.Wednesday
	1) 使用自带mimetypes得到更广泛的类型判断(audio,image,video)
		- note: 对历史版本生效
		- detail: rename SUPPORTFILES to _SUPPORTFILES
		
12. 2023.6.10.0.39.AM.Saturday
	0) !!!完全取消了向前兼容性!!!
	1) 完全重建架构，不向下兼容。
	2) 基于新的存储格式，现在加解密的文件io更快
	3) 支持了全大小文件的加密处理(现在不会再报错)
	4) 使用Chacha20基于nonce的算法，每个文件现在有不同的特征量
	5) 扩充b58到b60使编码更紧凑
	6) calibration_amount 为 -1 时将加密整个文件

13. 2024.2.13
	0) 此版本不具有向前兼容性!!!
	1) 默认使用更快的argon2_cffi和更安全的参数
	2) 扩充b60到b72使编码更紧凑
	3) 设calibration_amount参数默认值为2048
	4) 分离模块到thirdmod文件夹

14. 2025.9.7.11.56.PM.Sunday
	0) 此版本不具有向前兼容性!!!
	1) 更新了base72编码算法及其字符表，修复Windows下以base72重命名时可能触发的错误及解码错误
	2) 添加了一个命令行参数用以指定扫描路径

15. 2025.10.9.6.13.PM.Thursday
	0) 微调字节操作实现以增加性能

16. 2025.11.10.2.30.AM.Monday
	0) 修改文件名加密逻辑，现在文件加密后使用加密名字生成hash cover; Inplace encrypt file_name_b (changelog)

---

Update report:

使用rust重写整个程序：

1. 2025.11.10.4.5.AM.Monday
	0) 完成了rust版本的重写
	1) 编写了一个简单的命令行接口
	2) 编写了一个简单的测试
	3) 在安全性方面做了一些改进
	4) 本版本不具有向PY兼容性!!!

2. 2026.7.23.11.50.PM.Thursday
	0) 此版本不具有向前兼容性!!!
	1) 将密钥存储从Zeroizing<[u8;32]>迁移到LockedKey<32>(mlock/VirtualLock页面锁定内存, 防swap和coredump)
	2) SessionKey::generate()现在返回io::Result(mlock可能失败)
	3) 将base72编译期常量从lazy_static!改为const fn(利用Rust 2024 const-eval)
	4) 添加log_level模块, 实现运行时可配置的日志级别(log_info!/log_error!/log_debug!)
	5) 服务器TLS加密从ring provider切换到aws-lc-rs
	6) 更新rcgen 0.13→0.14, rand 0.9→0.10
	7) 在release profile中启用codegen-units=1(最大化单函数优化)
	8) 将默认最大连接数从16提升到32
	9) 改进WebDAV dispatch错误处理(返回500而不是panic)
	10) 在WebDAV content-type映射中添加avif格式支持

3. 2026.10.7.10.40.PM.Wednesday
	*本批为未发布的工作区改动汇总*

	1) 查看器重做
		① 缩放/平移改为只变换照片本身(不再缩放信箱边距)，任何缩放与位移都不会露出空白
		② 双指/滚轮以焦点为中心缩放，双击缩放至点击处(2.5×)或复位，最大 6× fit；1:1 上限 6× fit
		③ 下拉关闭：位移 1:1、横向阻尼 0.35；阈值取视口 12%(72–132px 夹取)或 >700px/s 快速甩动
		④ 顶部 chrome 改为浮在照片上的圆形按钮 + 文件名/位置，胶片条改为底部渐隐 scrim
	2) 图片信息面板(EXIF / track)
		① Rust 侧新增 `rcrm_media_metadata_async`(nom-exif 纯内存解析，不落盘)，JSON → 不可变模型
		② 面板按画廊习惯排版：大日期 → 文件名 → 位置行 → 相机块 → 标签行；橙色只用在 1:1 chip
		③ 只在解析成功后才声明"没有相机/位置信息"；解析失败或未取得字节时保持沉默
		④ 失败结果不写入缓存(下次打开重试)，解析回调有 10s 超时兜底
		⑤ 修复 WebDAV `getlastmodified` 只按 ISO 解析导致的空日期：现在兼容 RFC 1123 并按本地时间显示
	3) 播放器 chrome 重写
		① 密度按窗口最短边分档(compact/regular/expanded)，全屏不再放大控件；底栏新增极窄档位(≥~108dp 不再溢出)
		② 宽度预算：时间 → 跳过 → 倍速 → 剧集，音量滑条取剩余空间，不足 64dp 时隐藏并由静音键承担
		③ 顶栏(返回/标题/设置齿轮)在所有平台一致；设置面板或倍速菜单打开时 chrome 永不自动隐藏
		④ 修复倍速 chip 预算与绘制字体不一致、滚轮音量不夹取、点击目标被 VisualDensity 缩小等问题
	4) 直播照片不再落盘
		① media_kit 的 `Media.memory` 会写临时文件且只在 GC 时删除；改为 `LiveMediaServer`：仅回环绑定 + 128bit token，从内存提供 mp4
		② 播放器销毁时释放载荷，交接期最多驻留两份
	5) 零拷贝传输(本轮重点)
		① 新增 `services/native_bytes.dart`：HTTP 响应直接写进 native 缓冲(按 Content-Length 精确分配)，FFI 交接不再复制
		② 图片软解输入：AVIF/JXL/HEIC 原图经 native 抓取直达 Rust，省掉整帧复制；查看器 RGBA→ui.Image 的一次复制仍是硬限制(dart:ui 只接受 Dart 缓冲)
		③ 缩略图：新增 `rcrm_generate_thumb_webp_from_image`(解码→缩放→WebP 一次完成，输入借用)，移动端 AVIF/JXL/HEIC 缩略图从 3 次整帧复制降到 0
		④ 元数据：交接带容量(`cap`)精确释放；`DecodeBuf` 增加 `cap` 字段以支持解码器直接交出 `Vec`
		⑤ 修复 worker 超时后主 isolate 提前 free 输入缓冲导致的 use-after-free(改由 worker 持有一份)
	6) HEIC/HEIF 支持
		① `mobile-decode` 增加 `heic`(git dep，纯 Rust HEVC `backend-rust` + `parallel`)，与 AVIF/JXL 同一开关，桌面仍不编译
		② 新增 `rcrm_decode_heic_async` 与缩略图 kind_hint=3；容器方向(irot/imir)与 clap 裁剪由解码器处理
		③ 缩略图缩放使用与 JXL 相同的双线性采样；解码上限取 64MP(HEIC 不能用 AVIF 那套 8.3MP —— 手机 HEIC 普遍 12–48MP，照搬会把真实照片全部拒掉)
		④ 修复 HEIC 一开始照搬 AVIF 的 8.3MP 上限导致的"桌面 heic 解码不出来"(16MP 的 iPhone 照片被 LimitExceeded 拒掉)，并去掉 `#[cfg(test)] u64::MAX` 逃逸(正是它让测试全绿而 App 无图)，补端到端缩略图回归测试
	7) 其它
		① `flutter analyze lib test` 与 `cargo clippy --all` 均零告警；Rust 单测 46(含 mobile-decode)、Dart 测试约 250
		② 文档全面更新：README/README_zh、ARCHITECTURE、API_REFERENCE、BUILDING(含 ffmpeg≥9 TLS 与 Flutter 3.47 Impeller 两个环境级已知问题)、DESIGN、AGENTS
		③ 暂存区只读审查后的修复：去掉 _v2(不需要版本化，导出即 rcrm_media_metadata_async)；getlastmodified 统一到 UTC 口径(ISO 无时区不再按本地时间解释，否则同一目录内排序会偏一个时区)；查看器下拉关闭与返回键的双重 pop 合并为单一守卫(此前会把查看器下面那一屏也弹掉)；信息面板在答复未到时不再先断言 No camera/location information(改骨架占位；骨架比它替代的那一块矮，因此答复到达时下方各行会有小幅位移——这是不撒谎的代价，原先"无跳动"的说法是错的)，EXIF 尺寸按 orientation 5-8 交换宽高，非整分数曝光时间不再写成 1/1 s；缩略图 Rust 快路径失败时只在"网络已给出终局答案"(请求被拒/空响应)才放弃，字节到手而 Rust 解码器拒绝的情形仍回落引擎解码(不同解码器，能读我们读不了的文件)——原先一律放弃会让查看器能显示的文件永远没有缩略图；元数据缓存淘汰不再驱逐在途项；worker 回复超时改为 kill 卡死的 isolate 并在其真正退出后回收输入缓冲；encodeRgba 全帧拷贝由两次降为一次(回退路径复用同一缓冲)
		④ 低优先项收尾：媒体元数据模型去掉裸 as(错类型字段不再让整份文档退化为 none)；播放器文本测量加缓存(按 文本+样式+缩放 记忆，上限 128)；控制栏在最窄宽度下继续降级(先让全屏、再让静音，播放键恒在)并修掉无条件 gap 导致的 2px 溢出，像素扫描下界从 120dp 降到 40dp；Rust 元数据导出的违约分支区分 no buffer/empty input/bad capacity 并按声明容量接管释放(不再两侧都不释放)；同步的缩略图导出加 catch_unwind(解码器 panic 不再跨 FFI abort)；鉴权头读取全部改为缺键即降级(5 处)；NativeFetch.retryWithCopy 真正被生产代码使用——分块响应(无法精确分配)回退到通用取字节路径，此前会直接丢掉缩略图；查看器下拉关闭改为只在 1x(fit) 生效——放大状态下拖拽只做平移，不再能从顶边把整屏拽掉(原先的 top-edge 判定已删除，连同只服务于它的 atTopEdge 通道与 ViewerZoom.atTopEdge)
		⑤ Windows 自绘标题栏拖动改为**鼠标发起**的移动：`rcrm/window` 通道 startWindowDrag → runner ReleaseCapture(); PostMessage(WM_NCLBUTTONDOWN, HTCAPTION, 0)（Electron/Tauri 同款）。原因：startDragging() 的 WM_SYSCOMMAND+SC_MOVE 被系统当作键盘移动，**Win11 会吸附、Win10 完全不吸附**；新做法两者都能吸附。fullscreen 时不拖（Dart isFullScreen() + runner WS_THICKFRAME 兜底）。曾试的子窗口 WM_NCHITTEST/HTTRANSPARENT 委托已放弃（与 fullscreen 冲突、会出现残影）。最大化时的客户区几何归 window_manager 的插件代理（TitleBarStyle.hidden 下它接管每个 WM_NCCALCSIZE），runner 里那个 case 已确认是死代码并删除
		⑥ open-code-review 只读审查后的修复：缩略图 worker 的输入缓冲改为**主 isolate 单一所有者**（worker 不再释放），按 isolate 归属登记、只在该 isolate 退出时或其回复到达时回收，`NativeBytes.reclaim()` 幂等——原来的两处会 use-after-free / double free；同批修掉被换代请求的缓冲泄漏、exit 事件不标记 worker 死亡（后续请求白等 15s）、spawn 失败泄漏 isolate 与两个 ReceivePort；AVIF 解码失败不再泄漏 dav1d context（RAII 必关）、`alloc_buf` 检查空指针、rav1d 的 frame_size_limit 从 0 改为接上限（容器 ispe 可伪造，此前是唯一闸门），AVIF 上限参数化并**删除 `#[cfg(test)] u64::MAX` 逃逸**（回归测试改为：生产入口必须接受 39MP 夹具、而低于文件体量的 ceiling 必须拒绝它），并把三个软件解码器的上限**统一为 64MP**（AVIF 原为 8.3MP，会拒掉所有 12MP 手机照片；JXL 与 HEIC 已是 64MP，另加 65536 边长与画布像素的 sanity 上限），三个 decode 导出与 metadata 同形改用 `Builder::spawn` + `catch_unwind`（线程创建失败不再 abort 进程、解码 panic 不再让 Dart 空等并占 gate 名额）；`window_drag` 通道不可用时仍回落到 startDragging（此前"回落前 return"会让旧 runner 只能拖一次）；AVIF 未处理 irot/imir 一事写成显式限制说明；文档修正：README 快速开始补 `--http`（原来起的是明文 FTP）、CHANGELOG 修复一个吃掉 `r` 的孤立 CR、DESIGN 补控制降级阶梯、ARCHITECTURE 修正 ⓘ 不在 AppBar、rust_bridge 所有权注释改为"取得所有权"

4. 2026.10.13.1.11.PM.Tuesday
	*本批为 2026.10.10–10.13 的改动汇总(共 27 个提交)*

	1) 播放器全屏方向改为策略，且两端都真正做得到
		① 五个值 `fill | system | device | portrait | landscape`，面板给四个策略(两个锁定合成一个，选中后下面出现方向行)：Fit(跟随视频，宽视频锁横屏)、System(只按系统允许的来，旋转锁有效)、Follow(按手机实际机位，**无视旋转锁**)、Lock(定住某一方向)
		② 重建的原因：旧的 Auto-Rotate 开关写着"Ignore system rotation lock; follow device orientation"，而它唯一的调用 `setPreferredOrientations`(四向)在 Android embedding 里被解码成 `FULL_USER`，平台文档原文是 "Respect the user's sensor-based rotation preference"——锁开着的手机上，它开与不开完全一样。真正无视锁的是 `FULL_SENSOR`("Ignores user's setting to turn off sensor-based rotation")，任何 `DeviceOrientation` 列表都表达不了它，所以 App 为此有了自己的通道 `rcrm/orientation`
		③ iOS 用自己的方式到达同一处：`UIDevice.current.orientation` 是**硬件机位**(不受旋转锁影响)，再把界面显式搬过去——iOS 16+ 用公开的 `requestGeometryUpdate`，13–15 用长期沿用的 `setValue(_:forKey:"orientation")` + `attemptRotationToDeviceOrientation`。注意 `UIDeviceOrientation.landscapeLeft` 对应界面的 `landscapeRight`，读这个传感器的 App 都必须反转
		④ 另一处坏在同一件事的两半：旧代码只判断一次，读的还是播放器常常尚未上报的尺寸(未知就当横屏)，之后再不重算——竖视频会整场锁在横屏。现在 进/出全屏、换策略、`videoParams` 尺寸到达、离开播放器 都会重算；`fit` 在尺寸未知时**什么都不强制**(对谁都不知道的形状，任何猜测都会锁住画面，而锁定还会顺带阻止用户转动手机去看宽视频)
		⑤ 顺序有讲究，且被抽成带测试的纯函数(`applyOrientationRequest` / `releaseOrientationRequest`)：进是"先 mask 后 sensor"(iOS 只在自己 mask 允许时才执行几何请求；Android 上两者写同一个 Activity 属性，所以 sensor 必须最后)，出是"先停 sensor 再改 mask"(iOS 停止跟随之前会一直强制几何，与新 mask 打架)
		⑥ 审查抓到一条 high：我为 sensor 请求加的 latch 使**第二次** `_applyOrientation` 只写 mask(=`FULL_USER`)而跳过 sensor，Follow 静默退化成 System——而且走的是常规路径(尺寸到达、跳转新播放器、700ms 重施)。两个原生半边本就幂等，latch 删除，sensor 在每次 mask 之后重发
		⑦ 未验证：没有安卓真机也没有 macOS，Swift 编不了，各策略的真实旋转一次都没跑过；**iOS 在旋转锁打开时是否真的执行那个几何请求**未知——若不执行，诚实的收尾是把 iOS 的 Follow 撤掉，而不是留着平台不肯兑现的承诺。iOS 16 以下那条是未公开 API，作为显式接受的风险写进代码与文档(替代方案：抬到 16，或 16 以下不提供 Follow)

	2) 移动端音量绑定系统媒体流
		① `use_system_volume`(Settings→Display，移动端默认开、桌面端不提供)：音量控件驱动**设备**的媒体流，播放器自身钉在 unity(同时写会叠两次衰减)，开屏以手机当前音量为准，绑定期间不写回 `player_volume`(那个数字属于手机)
		② 算术只在 Dart(`services/system_volume.dart`)：平台只回原始流数字(`index`/`min`/`max`/`muted`/`lastAudible`/`fixed`)并接受 index，于是百分比、量化(15 档手机没有 43%，只有 40%)、取消静音回退都是纯函数并单测
		③ 原生半边：Kotlin 走 `STREAM_MUSIC`、flags 0(系统的音量面板绝不盖住视频)，两条变更源——过滤过的 `@hide VOLUME_CHANGED_ACTION` 广播 **加** 只看音量键的 `Settings.System` ContentObserver(亮度滑动每帧都在写 SCREEN_BRIGHTNESS，不过滤会狂响)；iOS 用 `MPVolumeView` 自己的 slider 同时读写(`outputVolume` 只在活跃 session 上有意义，而本 App 不该去抢那个 session)
		④ 两轮只读审查共 22 条、其中 6 条是真 bug，都写进了测试：可听记忆必须从 0 开始(否则静音开局第一次 unmute 直冲满格)、量化回声没人收到(`ValueNotifier` 对相等值不通知，所以设备的落点要显式应用回条)、会话中途变 `fixed`(插上 HDMI/USB 声卡)、第二次 seed 只确认不重新采纳、写到被静音流上的那次写入不能被"已经在这一档"跳过(那次写入正是解除静音的动作)、非有限值必须在入口拒绝(`clamp` 放过 NaN 而 `round()` 会抛，从 unawaited 写入里抛就是不处理的异步错误)

	3) 两个竖向手势共用一套算术，步幅缩短
		① 音量那半边原先每帧回读进度条，而绑定之后条上放的是**设备落到的档位**：15 档手机 6.7%/档，慢滑什么都不动、1px 抖动跨档还会逆着手指往回走。现在两半共用一个只属于手指的累加器(`utils/swipe_value.dart`)，滑行中不采纳设备的答案，抬手时采纳
		② 步幅从"一整屏高"改为 `kVerticalSwipeSpanRatio` = 0.6 屏高(约 1.67 倍)：竖屏全屏下 9px/% → 5.3px/%。"一整屏"从来不是为手指选的，它是除出来的结果，而行程变诚实之后才显出慢
		③ 两端 clamp 不环绕、1px 抖动只动 1px、没有高度的那一帧不动值；测试把这个选择的两端钉住(必须短于整屏，又不能短到 1% 不到一个像素)

	4) 视频标签的第二种排布 + 未分组图片平铺
		① 视频标签可在工具栏 Organize 切换"按文件夹/按格式"(记住 `video_classification`，默认 `none` 就是原来的平铺)，带 2×2 海报预览与钻入视图；分组复用 `MediaLibrary.buildAlbums`(分类从写死改为参数，枚举改名 `MediaClassification`)，视频侧的组是**派生**的所以切换不重扫；两个标签各传自己的分类，谁也不能把对方重新分组
		② 图片标签的 'None' 名不副实：它建了一个叫 "All Images" 的相册，等于"要打开的分组"，正是这个设置说不做的事。现在 `none` 不产生任何相册、平铺显示(与视频标签同词，改名 'Ungrouped')；首页只认相册，所以给它一个平铺相册入口，否则那些照片从首页够不到；分类判断收敛到一处(原先两处写法已经漂移)
		③ 图标树摇的坑(本批踩到两次)：`Icon(groupingIcon(key))` 这种运行时查表对 release 的图标 tree-shaker 不可见，字形会变成**空的**(实测 Organize 与 By format 空、而硬编码的 `Icons.folder` 正常)；改成在使用点写 `const Icon(...)`，树摇后的字体 11,464 → 11,684 字节(缩略图对话框那处 11,464 → 12,084)。关掉树摇能"修好"，代价是 1.6MB

	5) 播放器的跳跃历史，与"离开播放器只有一种退场"
		① `providers/video_jump_stack.dart`：会话级跳跃栈，上限由设置 `video_jump_history_limit`(1..50，默认 10)控制；前进跳转记录**被离开的**那个视频，Back 弹出并播放它。一个 `back: true` 标志同时决定"是否记录"与"播哪个转场"，两者不可能不一致
		② Back 的转场就是平台自己"揭开下一页"的那一套(Android 逐值复刻 `FadeForwardsPageTransitionsBuilder`，450ms 不动；其它平台直接做框架给被揭示页面的那次调用)。手写一套滑入对所有平台都是错的：iOS/macOS 从 -1/3 走 Cupertino 曲线，Windows/Linux 的 zoom 根本不横向位移
		③ 传输栏的上一首/下一首改为在**同一个播放器里**换片(`_playInPlace`)：全屏、PiP(连同拖到的位置与滚动位置)、倍速、音量、亮度、chrome 可见性全部"由构造保证"存活，屏幕上没有任何东西移动；Back 仍走路由步并带平台的返回方向转场——"离开这个视频"和"换一个播"是两件事
		④ 一个视频怎么离开播放器，只由它在做什么决定：Back(历史空/历史走完)与 Home 都走同一 pop。Home 原先在 `popUntil` 前 `p?.stop()`，而停掉的 `Player` 不画帧——同一步少了画面；改为由路由自己的 `dispose()` 停。`leavePlayerForLibrary` 用 `PosterQuietRoute.previousRoute` 先把中间那一屏**无动画**摘掉，否则从搜索结果打开的播放器会一次滑走两屏
		⑤ 退场的 chrome 在**退出开始**时恢复，而不是结束时：全屏横屏视频以前先 pop、再恢复系统栏并旋转，于是库以横屏到位然后又重排
		⑥ `_go` 不再停/销毁旧播放器：被替换的路由在整个转场期间仍在树上(实测 300ms 里 0/100/200ms 在、settled 后消失)，提前拆会把画面黑掉整段——那片黑是纹理被销毁的，不是路由缺席；改为静音，并由该屏幕自己的 `dispose()` 收尾
		⑦ 不能动作的 chrome 不再画：上一首/下一首按可用性出现(没有历史就没有 Previous，Related 空就没有 Next)，Home 只在它与 Back 是**不同**动作时出现(栈空时 Back 自己就离开了)。灰掉的占位被否掉：它会在每个宽度都为音量滑条占着空间

	6) 缩略图缓存可管理：评分分档、逐档删除、自动精简
		① 评分是纯函数(`utils/thumb_cache_policy.dart`)：上次使用(权重 3)、生成时间(1)、体积(-2)，各自按**本缓存的 MEDIAN** 归一化，所以不从外部断言任何事——三年前生成、昨天打开过的缩略图排在"上周生成、从没人打开"的前面。分档切在评分序的**两个最大间隔**处，且只有相对本缓存的中位间隔显著时才切；没有形状的缓存退化为等三分
		② 访问记录**另立文件**，因为文件的 mtime 就是生成时间：读取绝不能重写它(`setLastModified` 会毁掉整个评分所依赖的那条轴，而 `stat().accessed` 在我们发布的平台上都不可靠)。命中写 `_thumbs_used`，放在条目**旁边**而不是中间(否则每个列表器都要学会跳过它)，节流并按现存条目剪枝
		③ 对话框是唯一入口：每个档位行删自己那一档(整档，预算没有否决权)、`Auto trim` 按最冷优先裁到就地可切的目标、`Delete all` 用错误色并在缓存为空时一并置灰(活着的控件不能动作就是死控件缺陷)。年龄写成年龄("generated 2 months ago")，不写日期
		④ 顺带两次重构：对话框的三个互斥意图从"四字段 record + 调用方猜"改成 `sealed class ThumbCacheIntent`(没意义的组合造不出来)；访问日志从 `ThumbCache`(390→297 行)抽成 `thumb_cache_access_log.dart`(98 行)，公开 API 不变所以九个缓存测试文件一行没改

	7) 截图策略成为移动端设置，默认不允许
		① Settings→Privacy→Allow Screenshots，移动端专有，**默认关**：库是解密后的媒体，一张截图比会话、App 和密码活得久。策略由平台执行，走自己的通道 `rcrm/screen`(Android 一个 window flag，iOS 没有等价物可买)，推送是刻意 fire-and-forget，恢复设置绝不等待平台答复
		② Android 原先在 `onCreate` 里无条件 `FLAG_SECURE`；这一个 flag 独自承载整条策略(截图空白、录屏干净、recent 预览隐藏)，现在独立成 `ScreenCaptureChannel.kt`，仍在 Dart 存在**之前**应用(启动那一刻的答案绝不是"可截")，并按进程记住选择，这样窗口重建后回来的是用户的选择而不是启动默认值
		③ iOS 根本无法拒绝一张静态截图(系统只在事后告知)，但它能告知"屏幕正在被录制/镜像"和"App 不再前台"(系统正为 app switcher 拍照)——iOS 半边覆盖这两种情形，注册即武装(fail closed)，允许截图后解除。行的文案说平台自己的真相(`capturePolicyNote` 是"这个平台能否拦下静态截图"的纯函数)：一个在某个 OS 上悄悄换了含义的开关，比没有开关更糟
		④ 路上量到一个陷阱：在 `load()` 里 await 那次通道调用会让**每一个**调用 `load()` 的既有测试卡死(`testWidgets` 的假时钟下真实通道往返永不完成，两个测试各烧满 10 分钟超时)。于是两道闸：启动推送不 await，没有截图面的平台根本不问

	8) 存储访问层：Android 的全文件访问终于有人去要
		① 清单里一直声明着 `MANAGE_EXTERNAL_STORAGE` 与读写对，却从来没有人请求过。库是由本地服务器按**真实路径**打开的，所以 SAF 的单目录授权覆盖不了它，`READ_MEDIA_*`(API 33+，MediaStore 媒体类型授权)也覆盖不了
		② 通道 `rcrm/storage` 报**三个字段**而不是一个布尔：`sdk`、`granted`、由哪条流程授予(`none`/`dialog`/`settings`)+ `canAsk`。API≥30 全文件访问是 **app-op**：声明不授予任何东西、`requestPermissions` 对它无效、`Environment.isExternalStorageManager()` 是唯一诚实的答案，去 `ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION` → `ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION` → 应用详情(前两个在设备上可能不存在)；API 23–29 是普通运行时权限(Android 10 另需 `android:requestLegacyExternalStorage="true"`)；API<23 安装即授予，无需求
		③ 三个陷阱：`request` 绝不持有 `MethodChannel.Result`(两条流程都会离开 Activity，改由 Dart 在每次 `resumed` 重读状态——那是用户从别的 App 设置页回来的唯一信号)；`shouldShowRequestPermissionRationale` **不是**"是否问过"的记录(它对从未请求过的权限也答 false，会让全新安装在 6–10 上被告知"安卓不会再问")，原生半边自己记一笔、写在**结果**回调而不是发起时(对话框期间什么都还没决定)；文案是报告状态的纯函数
		④ 要权限不阻断选目录(系统选择器两种情况下都会给路径)，但一旦有目录，设置页就明说"现在还读不了"——正是它消除了那个静默的空库。设置行只给**一个**可操作入口：行的点击加上同动作按钮就是同一件事做两遍

	9) 其余修复与依赖
		① ffmpeg≥9 默认校验 TLS 对端，桌面海报全部失败：海报命令传 `-hide_banner`(全局，放最前)与 `-tls_verify 0`(**输入**选项，必须在 `-i` 之前，放后面会被静默忽略)，放宽只限这一个子进程(Dart 客户端仍然钉证书)。接着发现上一个提交把**所有**桌面海报清空了：`-tls_verify` 是 `tls` 协议的输入选项，ffmpeg 在选定协议之后按名字解析、该协议没有这个名字就整条命令中止，而本 App 自己的服务器是 `http://127.0.0.1:<port>`，于是 "Option tls_verify not found."、每个视频零输出。现在只对 `https` 追加该标志(实测 9.0.2：file/http + 标志 = 失败；http 无标志 = 15851 字节 JPEG；https + 标志 = 成功；https 无标志 = 证书校验失败)
		② 诊断面板的"样本文件可读"为了打印长度拉了**整个**视频(`getFile` 就是 `resp.stream.toBytes()`)：改为 `getFileHead(path, maxBytes:)`，上限被两侧执行(请求带 `Range: bytes=0-N-1`，读满 N 就 break 并取消订阅)，面板报告"读到了什么"而不是"文件多大"。测试统计真正进入 Dart 的字节数——删掉那个 break 会报 4,194,304 字节对 256KiB 上限
		③ 查看器：下拉阈值 +30%(`min(172, max(94, h*0.156))`)、翻页冷却 200ms(-33%)、状态栏随 chrome 隐藏与恢复(resume 时按真实的 `edgeToEdge`↔`immersiveSticky` 变化重施，因为平台只对**变化**动作)、角标移出被下拉/缩放的那一层(随 chrome 淡出而不是跟着手指走)、直播照片用与横向拖拽同一道闸阻断下拉
		④ 播放器：方向锁引入 dominance ratio(只看 12px slop 会把 30px/29px 的近对角手势判成 seek，从而藏掉整个控制栏)、拖动进度时控件保持可见、Esc 让位给倍速菜单
		⑤ 媒体：Rust 的拒绝不再是终局(回落引擎解码)、Dart 取字节有上限、播放器路由期间暂停海报池、缓存键带库身份、图片排序方向持久化
		⑥ `build_android.sh` 补上与 `.ps1` 同样的 jniLibs 陈旧合并重置：桥刚重建而 Gradle 仍留着合并状态快照时，`mergeReleaseJniLibFolders` 会哈希失败(构建直接死)，更糟的是 `packageRelease` 对陈旧合并保持 UP-TO-DATE 而 APK 里没有 `libapp.so`/`librcrm_flutter_bridge.so`，构建却报 SUCCESS
		⑦ 依赖：`file_picker` 13.1.0(11.0 起 API 静态化，`FilePicker.platform` 是删除而非弃用，两处调用改用 `FilePicker.getDirectoryPath()`；12.0 拆成按平台包并连带强制升级 win32 5.15→6.4、package_info_plus 9→10、wakelock_plus 1.5.2→1.8.1、dbus 0.7.15→0.8；其 Android 模块自己按 `builtInKotlin=false` 应用 KGP，于是 12 个插件里再没有声明 KGP 的，Flutter 的 "future versions will fail to build" 警告从 Android 构建里消失)；`camera` 0.12.1(CameraX 1.5.3→1.6.2，对我们这条路径唯一的行为变化是 `initialize()` 与错误处理里新增的 `_isDisposed` 守卫——正是扫描页销毁一个仍在初始化的 controller 时可能撞上的崩溃)；`mimalloc` 0.1.52(`libmimalloc-sys` 0.1.49 起不加 `v2` feature 就编 v3 树，旧的 `features = ["v3"]` 是唯一挡着升级的东西；实测 v3 线路不变，mimalloc 3.1.5→3.3.2)；`archive` 4.5.1；`Cargo.lock` 若干传递依赖刷新

	10) 文档、审查与门禁
		① 单测文件里承诺的运行命令 `dart test test/rcrm_gui_test.dart` 从来没成功过(Dart VM 载不动：`webdav_client.dart` 一路链到 `dart:ui`)，改为 `flutter test`(实测 23 个测试)
		② 缓存文档(AGENTS/ARCHITECTURE)追上代码：分档不再是评分三分位、"勾选档位"的选择模型已删、每个档位行删自己
		③ 审查：本批经过 open-code-review 只读审查数轮(音量两轮共 22 条、方向一笔 18 条)，其中 high 一条(方向 latch 让 Follow 退化成 System)是被三个文件分组各自独立报出的同一条。两条明确**未改**并写明理由：iOS 16 以下的未公开 API(作为显式风险接受，替代方案留给产品决定)；`fit` 在视频尺寸未知时发出的请求与 `system` 相同(理由见第 1 条 ④，因此保留不改)
		④ 门禁：`flutter analyze lib test` 零告警；`flutter test` 649 全绿(本批起点 485)；`gradlew :app:compileDebugKotlin :app:processDebugManifest` BUILD SUCCESSFUL；`cargo build --locked` 与 `cargo test -- --skip compare_` 通过

4. 2026.10.14.9.30.AM.Thursday
	*本批为未发布的工作区改动汇总(接上一批,尚未提交)*

	1) 播放器：按住画面 2 倍速，悬浮窗口也有
		① 长按是倍速手势(video.js 的那套)，现在三个表面都有：两个平台的画面与悬浮窗。按住的起点倍速在抬手时放回；长按一旦获胜，Flutter 必配对结束、中途移动只报 move-update——所以"按住滑成拖动"不会发生，也不会把倍速丢在 2x 上
		② 收尾不变量：配对只由接管长按的那个表面送达，拆掉表面就必须由拆的人自己结束长按。全屏切换与 PiP 消失两处有此收尾；悬浮窗自己携带 2x 角标与拖拽/长按同场的手势(竞速已由长按 500ms 获胜解决)
		③ **审查发现并已修复**：PiP *出现*的方向漏了收尾——滚过视频时页内画面被换成空槽，其上的识别器静默销毁，进行中的长按被遗留(倍速卡在 2x、角标常亮，且下一次长按会把"要放回的倍速"记成 2.0 变成粘性)。桌面按住鼠标 500ms 后滚轮即可触发。修复：`_onScroll` 里 `_longPress2xEnd()` 提到 `_pip` 翻转处，两个方向共用一次调用(方法按 `show2x` 幂等)；框架保证(槽位替换中途长按收不到结束回调)以测试钉住
		④ 悬浮窗刻意不带"回库"的按钮：✕ 只关窗、⛶ 回到画面；200px 的窗里第三个按钮是在和真正干活的两个抢地方

	2) 播放模式上传送栏：模式 chip 与随机播放
		① 播放模式(Loop All / Shuffle / Loop One / Pause After)从设置面板的第一行搬到传送栏自己的 chip(`utils/player_playback_mode.dart`)：模式是看着片子改的决定，为它离开画面去开面板是走错时机；一个设置只留一扇门。chip 用图标报告当前模式(`repeat`/`shuffle`/`repeat_one`，默认的 pauseAfter 是空心停止圈)，非默认态持强调色——与倍速 chip 同一条规则
		② chip 的菜单沿用倍速菜单的 Ash 面板，但每一行带自己的说明句：四个模式需要四句解释，读它的时候正是选它的时候。Shuffle 与 Loop All 的句子只差一个短语(从 Related 里随机抽一部 vs 取 Related 的下一部)，因为这就是两者的全部差别
		③ **Shuffle 的抽取范围是 Related 列表**(不是全库——经确认)：观众结束时正看着的那份列表，同目录优先、跳跃历史已排除；Loop All 取列表顶(Next 按钮会放的那部)，Shuffle 在其中均匀抽一行(`utils/shuffle_next.dart`，纯函数+注入 RNG 可复现)。两者都走 8 秒可拒绝的 Up-next 卡片，卡片的说明行以 "Random pick" 开头；换到不提供下一部的模式会撤回已开出的卡片
		④ **模式不改变 Next 按钮的行为**：Next 的承诺是播放列表里看得到的那一部，一个悄悄改写它的模式会把承诺打破；模式只决定"文件结束时提供什么"
		⑤ 宽度阶梯改为严格 LADDER(不再是贪心填空)：一旦某项装不下，其下全部不参与。贪心会让更便宜的控件挤进更优先者腾不出的槽位——倍速 chip 的宽度随速率文本变化，1.25x 时比模式 chip 宽，窗口拖动 1dp 两个 chip 就会互换。模式的优先级排在 skip Back 之前，凭据是"门"而非频次：Back 有移动端系统手势与桌面 Esc 兜底(都走 `_handleBack` 回溯跳跃历史)，而模式只有这一个 chip。代价(已实测)：窗口化模式下 prev 按钮在约 374-432dp 让位；音量滑条在窗口化约 470dp 才回归
		⑥ `playback_mode` 白名单接受 'shuffle'；未知的历史值读作默认 pauseAfter(往返有测试)
		⑦ 精修(impeccable 的 polish，只作用于本批改动)：菜单的说明句原为 `white38`——Ash 上 **3.6:1**，低于 11dp 文字的 AA 下限 4.5:1，而它正是设计系统明文禁止的那类"为优雅而用的浅灰"(`white38` ≈ #717171)。四句说明是菜单为什么带文字的全部理由，暗室里读不出的解释不是解释 → 改用系统自己的次级文字 token **Silver**(`#AAAAAA`，Ash 上 7.5:1；选中行的焦点高亮上仍有 5.3:1)
		⑧ 行高与上开位移都改为**测量**(不再假设)：`PopupMenuItem.height` 是*最小值*而非高度，M3 又不给菜单行任何纵向内边距——说明句换行超过名义 78dp 时行会自己长高(1.3x→95dp、1.6x→139dp)，下一行的标题于是紧贴上一行的句子。现在按行真实宽度测出「标签 + 2dp + 说明句换行高度」，超过地板时上下各留 8dp；菜单的上开位移用同一测量(原来是 `78 × 4 + 16`)。chip 在窗口底部，菜单只要低一行就会压住*打开它的那个控件*——1.6x 下实测比预期低 21dp(真实高度 481 vs 假设 312)。写测试时才现形的同族缺陷：说明书必须在*菜单自己的*文字环境里测量(Material 菜单项的 `labelLarge`)，用 bar 的默认样式量会在长句上少算一行
		⑨ 精修的验证：新增 3 条测试(说明句对比度 ≥ 4.5:1；上开位移在各字号档等于菜单**真实**高度；有空间时菜单不越过 chip；行被内容撑高后仍留空气)。渲染工具(4 个宽高 × 3 档字号 + 短窗 + 倍速菜单对照)实测：1.0/1.3/1.6x 下菜单底边都精确停在 chip 上方 8dp。**无解的一例**：窗口比菜单还矮时(420×300)菜单被钳到屏幕并滚动到当前模式——300dp 高的窗口放不下四行带解释的选择，此时四个模式仍可达(可滚)，只是不能同时看见
		⑩ 未验证：无安卓/iOS 真机，chips 在真实设备上的触感(尤其 menu 在刘海屏上的上边界)未实机跑过；桌面端 320-350dp 的极端窄窗里 chip 不出现，此时模式暂不可达(无第二入口，刻意不设——两扇门是这个仓库不收的)；真机上大字号(1.6x)下菜单被钳后的滚动手感未验证
		⑪ **重做(impeccable polish 第二轮，只作用于模式组件)**：上一轮只修了字色与位移，整体没有重看；这次按渲染证据把组件重做了一遍，概念不动(一个 chip + 一个菜单)，三条实测缺陷：
			① **菜单是文档，不是菜单**：四句说明各两行，行高 78dp(1.0x)/139dp(1.6x)，竖屏手机实测菜单 350dp(1.6x 时 481dp)——640dp 高的屏幕上盖掉半屏，1.6x 时超过 891dp 屏幕的可用高度。四段等重的解释也把"选哪个"这件事淹了
			② **chip 的点击区就是它的脸**：`PopupMenuButton` 不给子控件加内边距，实测 23×21dp，而同一行的每个控件都是 40×40；宽度预算也只算 23dp
			③ **选中行是一整块 M3 highlight**(Ash 上 ≈ `#3A3A3A`)：95dp 行高时它像一层面板，底色/橙字/勾/橙图标四个信号在说同一件事
			④ 改法：说明句压到一行(≤32 字符)：`Next video in Related, 8s` / `Random video in Related, 8s` / `Replay this video` / `Stop on the last frame`——"8 秒可拒绝"的细节留在卡片上，菜单只回答"结束之后会发生什么"；行高地板 78→48dp，实测菜单 **192dp(1.0x)/212(1.3x)/252(1.6x)**；420×300 短窗现在 1.0x/1.3x 都放得下(菜单底 248 < chip 顶 266)，只有 1.6x 仍被钳(252 + 上下 8dp 屏边 > 252 可用，物理无解)
			⑤ chip 分成"脸"与"目标"：脸 24×20(compact)/41×21(expanded)不变形，目标是 bar 自己的高 × 至少 80% 宽——32×40(compact)、32.5×40(regular)、41×44(expanded)。80% 不是 100%，因为 40dp 会让 **375dp 手机的倍速 chip 掉出阶梯**(实测总量 378.6 > 375)，而倍速没有第二扇门；32×40 已是原脸的 2.6 倍面积。tooltip 也从控件名("Playback mode")改成状态名("When the video ends: Loop One")，只报告不弹菜单时同样带
			⑥ 标签与说明句的间距 2dp(行高测量与绘制两处写死)→ 常量 3dp，两处共用；同一屏另外三处 11dp `white38`(方向说明、快捷键行、Up-next 副行，后者现在还要读 "Random pick")→ Silver，与菜单同一条规则、同一个暗室
		⑫ 重做的测试与验证：新增目标尺寸(375→32×40、1280→41×44)、菜单高度上限(<300dp，测试字体)、说明句 ≤32 字符；`_pumpBar` 改用 `tester.view.physicalSize`(旧的 `setSurfaceSize` 不传导到 `MediaQuery.sizeOf`，密度档一直错)，原对比度/位移=真实高度/行间空气/无 handler 不弹菜单等断言保留。`flutter analyze lib test` 零告警；播放器相关的 6 个测试文件 93 条全绿，全量 `flutter test` **684** 全绿；渲染重跑 12 张(1280/360/420 × 1.0/1.3/1.6x + 短窗 + 倍速对照)逐张看过
		⑬ 重做的未验证：无安卓/iOS 真机；32dp 宽的目标在手指下的触感、菜单在刘海屏上的上边界未实机跑过；1.6x 文字 + 420×300 窗口仍不能同时看见四项(已写入 DESIGN.md)
5. 2026.10.21.9.40.AM.Wednesday
	*本批为未发布的工作区改动：二维码编解码 rxing → zxing-cpp*

	1) 依赖替换：rxing 0.9.3 → zxing-cpp 0.5.3（C++ zxing-cpp 3.1.1，官方 Rust wrapper，`bundled`）
		① 依据 `D:\Belong\tmp\xing_bench\cross_bench\REPORT.md`（4900 张退化图）：整体识别 74.0% vs 72.2%，QR 81.9% vs 80.9%，Aztec +10.6pp、小码/低分辨率 +7.3pp；QR 中位耗时约为 rxing 的 0.45（全格式 0.12–0.33），官方 wrapper 与直连 C++ 逐图 4900/4900 一致、FFI 开销 <5%。本仓库只用 QR 的编与读，这两个 QR 数字就是替换的依据
		② `qr_scan.rs`：`ImageView::from_slice(..., ImageFormat::Lum)` + `BarcodeReader`（QRCode only，try_harder/rotate/invert/downscale）；JPEG/RGB/BGRA/strided-luma 四个入口仍汇到同一条 tight-luma 路径。`qr_gen.rs`：`create(QRCode).options("ec_level:M")` 生成模块图（自带 4 模块静区），按整数倍最近邻放大到 2048²，仍由 zenwebp 输出 lossless WebP
		③ 测试：`cargo test -p rcrm-flutter-bridge` 25/25（含 `generated_qr_scans_back` 生成→扫码闭环、JPEG/BGRA/stride 往返、`garbage_frame_returns_none`）
		④ 构建：`bundled` 用 CMake 编译 C++，需要 CMake ≥3.21 + C++ 工具链。Android 每 ABI 一个 `scripts/cmake/android-*.cmake` shim（ANDROID_ABI、ANDROID_STL=c++_static）；wrapper 对 `*-linux*` 发的 `-lstdc++` 在 NDK 上会先命中 legacy `libstdc++.so`，脚本把各 ABI 的静态 `libstdc++.a` 复制到 `target/android-stdcxx/<abi>` 并用 target-scoped `-L native=...` 改选它，再补 `-lc++_static -lc++abi -lunwind`。直接指向整个 ABI sysroot 会误链静态 libc，armv7 的 `__aeabi_*` 版本符号会报 `undefined version LIBC_N`。iOS 加 device/sim shim；Windows 上 cmake-rs 把 opt-level=0 映射成 CMake Debug（/MDd），根 `Cargo.toml` 用 `[profile.dev.package.zxing-cpp] opt-level=3` 固定到 release CRT
		⑤ 验证：host 全量 `cargo test` 通过；Android 3 ABI release 交叉编译通过（`build_android.ps1 -Release -SplitAbi` 连 APK 一起出包，三个 .so 的 NEEDED 只剩 libdl/libm/libc）；`cargo clippy --all` 与 `cargo clippy -p rcrm-flutter-bridge --features mobile-decode --all-targets` 零告警；Windows release bridge（DLL）构建通过
		⑥ 未验证：iOS/Linux/macOS 未在本机构建（无 macOS 主机）；真机扫码未跑，灵敏度依据是单测 + 基准报告

6. 2026.10.23.2.40.AM.Friday
	*本批为未发布的工作区改动：应用图标与品牌资产*

	1) 图标：Flutter 模板图标全部换成 rcrm 自己的盾牌 R
		① 源文件在 `.local_backup/select_rcrmicon/`（cc.svg 方形 mark、cc2.svg 横版 banner），现落到 `brands/design/logo.svg` / `banner.svg`；另加 `logo-monochrome.svg`（Android 13 主题图标：盾牌挖空 R，由系统着色）
		② 生成器 `brands/build_icons.py`：一条命令产出全部平台图标 + README banner。SVG 由 ffmpeg 的 librsvg 解码器栅格化（该 ffmpeg 无 librsvg 时回落 rsvg-convert），背景合成、圆角遮罩、尺寸缩放全部由 ffmpeg 完成，输出只有无损 PNG（.ico/.icns 容器内也是 PNG 或 32bpp DIB）；脚本不依赖 Pillow，只用标准库写容器
		③ 设计：源图透明，背景取奶油色 #F6F1E9（白底偏冷，深色会吃掉红盾的轮廓）；mark 占方形画布 94%（盾牌约 62% 宽、76% 高；第一版 78% 像白卡片中间的一枚小印章，已按反馈放大）；整体向下做 2% 光学微调（盾牌质心比外框中心高 3.8%，按外框居中会读成上飘；调后约 48.4%，上下留白 14%/10%）；自适应前景 62%（108dp 画布、72dp 安全圆内）；桌面 tile 圆角 22.5%；macOS 按 Apple 的 824/1024 画框内缩
		④ 平台：Android 传统 mipmap（48/72/96/144/192）+ adaptive（foreground/monochrome 108dp 系列）+ `mipmap-anydpi-v26/ic_launcher.xml` + `values/colors.xml`；iOS 15 个尺寸（RGB、无 alpha）；macOS 7 个（含 824 画框，128px 同时是标题栏资产）；Windows .ico 10 档（≤128 为 32bpp DIB，256 为 PNG）；Linux 新增 `linux/runner/resources/app_icon.png`，runner 从 `/proc/self/exe` 定位、用 GTK 设置窗口图标，CMake 把它装进 bundle 的 data/
		⑤ banner：`banner.svg` 生成 `brands/out/banner.png`（深色字）与 `banner-dark.png`（奶油字，做法是把 wordmark 的 #2B2D3A 替换为 #F6F1E9），README/README_zh 顶部用 `<picture>` 按 prefers-color-scheme 切换；另出 `brands/out/icon-1024.png` 预览与 `rcrm.icns`；banner 原稿左距 9%、右距 18%（重心偏左），锁排列整体右移 46/1024 改为左右各 13.5%
		⑥ 验证：Windows release 构建通过（rc.exe 接受该 ico），从 exe 提取 32px 图标确认已嵌入；aapt2 compile + link 通过（含 `<monochrome>`、颜色与全部 mipmap）；Pillow 校验 iOS 尺寸/无 alpha、macOS 尺寸/透明角、Android 各密度尺寸；重跑脚本输出逐字节一致
		⑦ 未验证：iOS/macOS/Linux 未在本机构建（无 macOS 与 GTK 主机）；真机/真桌面的图标观感未跑，32px 以下盾牌会糊（源图细节所限）

7. 2026.10.23.3.36.AM.Friday
	*本批为未发布的工作区改动：退出播放器后方向自锁*

	1) 修复：选择 Portrait 后退出播放器，库仍被锁在竖屏（Landscape 同理锁横屏；System/Follow 也会被同一个写者盖掉）
		① 根因：`_releaseOrientation` 在退出开始时把蒙版写回 all，但它的两个异步写者仍活着——`stream.videoParams` 在整个 pop 期间保持订阅（只有 `_go` 取消），进入全屏时的 700ms 重试也可能已排队。任一在 release 之后再次调用 `_applyOrientation`，就会把视频轴（或显式 Portrait 锁）盖回库的蒙版上。上一批的"相等即忽略"只保护了 Fit：它的记录是视频自身形状；Portrait/Landscape 的请求不携带 `fittedShape`，所以每次上报都被当成 news，pop 期间的那次便把竖屏重新锁上
		② 修复：新增 `PlayerOrientationSession`（`utils/player_orientation.dart`），把"最后发出的 fittedShape"与"退出闩锁"放在一起；`_releaseOrientation` 先 `release()` 再写库蒙版；`_applyOrientation` 在 released / `_navigating` / `_isRoutePopping` / `_disposed` 时拒绝写；`_onVideoParams` 交给 session 判断是否 news；700ms 重试改为可取消的 `Timer`，`_go` 与 `dispose` 都取消
		③ 测试：`player_orientation_test.dart` 新增 5 条 session 测试（release 后任何形状都不是 news、Portrait 锁在 pop 期间不再重写、released 后 record 无效、重进全屏重新武装、记录随请求走）；`flutter analyze lib test` 零告警；全量 `flutter test` **689** 全绿
		④ 未验证：无真机；真机上的触发时序（例如换片加载中按 Home）仍需设备确认

8. 2026.10.23.4.10.AM.Friday
	*本批为未发布的工作区改动：Follow 模式切片先闪 system*

	1) 修复：Follow 模式全屏切换下一个视频，屏幕先回到 system 方向再跳回手机姿态
		① 根因有两层。A：`_onVideoParams` 对非 Fit 策略也把视频形状当 news，切片时又重新应用一次 Follow；Follow 的请求在 Android 上是"先四向蒙版（FULL_USER，尊重旋转锁）再 FULL_SENSOR"，中间那一瞬就是 system。B：即便没有重复应用（例如路由步进后的 700ms 重试），这个"先 FULL_USER 再 FULL_SENSOR"的顺序本身也会闪一次
		② 修复 A：`PlayerOrientationSession.videoShapeIsNews` 增加模式参数；只有 Fit 读取视频形状，System/Follow/两个锁不再因形状上报重写请求
		③ 修复 B：`applyOrientationRequest` 增加 `writeMaskBeforeFollow`；屏幕只在非 Android 上传 true。Android 的 FULL_SENSOR 本身就是完整策略（允许四向、忽略旋转锁），先写 FULL_USER 只会制造中间态；iOS 仍保持 mask-first（geometry request 必须被 supported mask 允许）
		④ 测试：新增 3 条（only fit reads a shape、Android Follow 只发 sensor、非 Follow 请求仍写 mask），并同步更新既有 session 断言；`flutter analyze lib test` 零告警；全量 `flutter test` **692** 全绿
		⑤ 未验证：无真机；Android 上中间帧是否彻底消失、iOS mask-first 是否有可见过渡，仍需设备确认

9. 2026.10.23.4.30.AM.Friday
	*本批为未发布的工作区改动：OCR 审查与修补（接第 8 条）*

	1) 用 open-code-review v1.13.3（deepseek-flash）审查两份方向改动，并逐条核对回复真实性
		① 第一轮（4 文件，3 条）：A. 非 Fit 策略切片后只有 700ms 重试会重新应用，startFullscreen 的玩家可能延迟；B. 已发出的 apply 在 await mask 后还会写 follow，release 恰好发生在中间时 iOS 上 follow(true) 会晚于 release 的 follow(false)；C. release 保留 _lockedShape，reenterFullscreen 后在未知形状的 Fill 会 hold 退出前的轴。核对：A 的"默认蒙版 700ms"描述夸大了（正常从窗口进全屏走 _setFullscreen 会立即应用；只有 startFullscreen 路由步进/链式步进暴露），但立即应用仍是正确修法；B、C 成立
		② 第一轮修补：post-frame 在排 700ms 重试前先 _applyOrientation；writeFollow 闭包在 release 后拒绝第二次写（返回 true，避免 Android fallback 写回）；release() 同时清 _lockedShape，补 reentry 测试
		③ 第二轮（4 文件，2 条）：D. Android Follow 依赖通道，followDevice 吞错后不再写任何蒙版，坏通道会停在旧锁上；E. _setFullscreen(false) 没有取消 700ms 重试。核对：D、E 成立。修补：followDevice 返回是否送达，Android 未送达时回退写四向蒙版；全屏切换取消重试
		④ 复核：`flutter analyze lib test` 零告警；全量 `flutter test` **694** 全绿；第三次 OCR 结果见下

	2) 第三轮 OCR（4 文件，8 条）与最终收敛
		① 采纳并修：平台规则移入 `OrientationPlatform`（调用点不再传 bool）；Android Follow 未送达时回退四向蒙版；release 后 follow/mask 两个写入都由 `PlayerOrientationSession` 守卫（`followThrough`/`maskThrough`，可测）；`followDevice` 的 true/false/unsupported 三支有断言；重复文档与过时理由修正
		② 采纳冗余判断：即时 apply 之后 700ms 重试不再提供信息量，删除该 Timer 及全部 cancel 点；第 7/8 条正文中的 700ms 描述是中间状态，最终代码没有这个 Timer
		③ 第三轮第 3 条已过时：它说 `followDevice` 返回值没有测试，但那段断言是在 OCR 取快照之后补的，当前测试覆盖三支
		④ 最终复验：`flutter analyze lib test` 零告警；全量 `flutter test` **696** 全绿

10. 2026.10.23.4.55.AM.Friday
	*本批为未发布的工作区改动：目录选择即保存*

	1) 修复：FilePicker 选完目录后不持久化，必须按 Save/Start/Skip
		① 设置 → Managed Directories：`_DirEditor` 的增删/浏览只改本地列表，只有 Save 才调用 `saveServerConfig`；点外面或返回关闭就丢。改为每次增删/浏览后立即写；按钮改为 Done（`barrierDismissible: false`，返回也会先等最后一次写落盘），关闭后按最终列表是否有变化决定是否重启服务器
		② 首次设置：选目录只进 `_selectedDirs`，只有 Skip 会 `saveServerConfig`；`_connect` 的注释声称持久化，实际没有调用——选完目录直接启动服务器，下次启动就丢。改为 `_pickFolder`/移除即保存，`_connect` 启动前再持久化一次（只写 directories，bind/port 仍用已保存的值，避免把临时的 127.0.0.1:0 写进配置）
		③ 验证：`flutter analyze lib test` 零告警；全量 `flutter test` **696** 全绿；file_picker 是平台通道，自动化无法点击真实选择器，桌面/手机手动确认未做

11. 2026.11.7.10.50.AM.Saturday
	*本批为未发布的工作区改动：视频缩略图磁盘缓存部分失效*

	1) 修复：访问记录在普通浏览会话里根本不落盘
		① `ThumbCacheAccessLog.flush()` 在 `_loadedFrom == null` 时直接 return，而 `_loadedFrom` 只在 `load()` 里赋值，唯一调用点是 `ThumbCache.preview()` —— 也就是只有用户打开设置里的缓存对话框才设得上。于是一个只浏览、不清缓存的会话，每 64 次命中触发的节流 flush 全部静默丢弃，评分里权重 3 的「上次使用」轴整段不跨会话；下次 Auto trim 只能按 mtime 分级，会把「生成得早、昨天刚看过」的那批判成 cold 删掉。这正是「部分」封面下次不命中的来源
		② `_ensureDir()` 在目录就绪时 `await ThumbCacheAccessLog.load(d)`（`load` 幂等且只读），进程里第一次缓存操作就把日志来源设好；`manage()` 把 flush 从「没删任何东西」的分支移到 return 前，两条路径都写回；`clear()` 删除后 `pruneTo({}) + flush()`，不留指向已删条目的行
	2) 修复：写盘竞态，以及视频海报读路径没有坏条目自愈
		① 两处 `ThumbCache.write` 都是 fire-and-forget：`thumbnail_service.dart` 的 `_cache` 与 `disk_thumb_image.dart` 的 `_generate`。图片侧命中失败会 `remove` 自愈，于是一个并发格子可能在第一个格子写盘未完成时解码到半写文件、把条目删掉；视频侧更重——`generatePoster` 命中直接把 bytes 塞进内存 LRU 返回，`VideoPoster` 的 errorBuilder 只画灰块，坏条目永久留在磁盘且本次会话被 LRU 短接
		② `_cache` 改 `Future<void>` 并在两处生成成功点 await；`_generate` 的 write 也 await，且移到 decode gate 的 `try/finally` 之外（写盘不再占慢路径的槽位）；`generatePoster` 加 `refresh` 可选参数，`VideoPoster.errorBuilder` 用一次性守卫在 postFrame 触发 `refresh: true` 重来，与 `DiskThumbImage._load` 已有的「解码失败才删」自愈对齐
		③ 审查后撤销：一度在 `generatePoster` 的磁盘命中处加过 JPEG 魔数 + 2000 字节下限校验。`ThumbCache` 存的是**不透明字节**（同一目录里既有 JPEG 视频海报、也有 WebP 图片缩略图，只是 key 不同），把「这个 key 一定是 JPEG」写死在单一消费者里，等于靠命名约定而不是靠抽象保证正确性；一次命中还可能删掉自己的条目，读不再幂等，也与图片侧「解码失败才删」不对称。现在读是纯读、格式无关，坏条目只在真正解码失败的地方自愈
	3) 审查发现与范围
		① 审查清单里两条候选被生成链路证伪并撤销：`sharedAuthHeader` 未就绪（所有 poster 入口都在 `setSharedAuth` 之后；唯一绕过 `isRunning` 的 Skip 分支下 `mediaLibraryProvider` 为 null，一个 MediaItem 都没有）与 `settingsProvider.load()` 首屏抢跑（`/home` 必经服务器启动 + ping）。`net.dart`、`settings_provider.dart` 一行未动
		② 桌面默认 OFF 时运行中开开关、已生成在内存 LRU 的封面不回填，以及 `PooledImage` 已挂载格子不切 provider：确认是不影响使用的 gap，按「勿增实体」不处理
		③ 全批 0 新增文件 / 类 / 设置项 / 模型：`refresh` 是现有方法的一个可选参数，`_retried` 是现有 State 的一个 bool
	4) 验证与未验证
		① `flutter analyze lib test` 零告警；相关 5 个测试文件 28/28 全绿（含新增 3 条：未打开对话框的会话自动 flush 能落盘、manage 有删除时仍 flush、clear 写回空日志）；全量 `flutter test` **739/739 全绿**。默认并发在 +640、`--concurrency=1` 在 +276、分批在 +46 都撞上同一个 `flutter_test_listener.*` 删除竞态（全是 `flutter_platform.dart:786` 的环境错误，无断言失败），最后把 `TEMP`/`TMP` 指到独立空目录后一次通过——`C:\ProgramData\Temp` 下已堆 46 个 `flutter_tools.*` 残留，这是绕开残留锁最省事的办法
		② 未验证：坏条目自愈需要真机或手动构造半写文件；`generatePoster` 依赖 media_kit/ffmpeg 且会 arm 30s 空闲计时器，没有写自动化用例。无真机验证

12. 2026.11.7.12.50.PM.Saturday
	*本批为未发布的工作区改动：主题色 / 主题切换 / 系统·日间·夜间*

	1) 设计世界的扩展：一个世界，两种外观
		① 用户拍板「全量浅色」。原 `config/theme.dart` 明写 "Dark-only by design"，`DESIGN.md` 的 North Star 是 The Midnight Gallery，`PRODUCT.md` 把 clean white/blue 列为反参考。所以 Day 不是白色 SaaS 换皮：沿用 app icon 的奶油 `#F6F1E9` 作画布，五级 tonal ramp 原序反相（pitch/ash/char/coal/dim），主文字改近黑 `#1A1613`、次级 `#5C5348`（6.7:1），无阴影分层与强调色稀有度全部不变
		② 5 个预设强调色（Marquee 默认 / Safelight / Projector / Footlight / Neon），取自剧院·暗房·胶片世界。Night 用饱和原色（5.9–11.1:1 on pitch），Day 用加深变体（4.8–7.6:1 on cream，卡片表面 ≥4.7:1），`onPrimary` 随之从近黑翻白。数值用 `Color.computeLuminance()` 实测
		③ 默认 **System**：新装跟随 OS，Day / Night 可钉住。两个值各自持久化，读侧白名单兜底（不认识的值回落 System / Marquee）
	2) 实现
		① `config/theme.dart`：新增 `RCrmAccent`（key/label/dark/light/warm + `fromKey`）与 `RCrmAppearance`；`RCrmColors` 从 `static const` 改成运行时 getter（固定品牌常量仍保留 const），由 `RCrmColors.apply` 单点写入。`RCrmTheme.build(accent, brightness)` 是纯函数，`applyToContext` 在 `MaterialApp.builder` 里按 Flutter **实际选中**的 brightness 应用一次——`theme` 与 `darkTheme` 都是纯构建，不会互相覆盖全局快照
		② 没有用 ThemeExtension / 逐处 `Theme.of(context)`：`RCrmColors` 已有 71 行调用点，其中多处是静态方法与 const 表达式；可变快照与仓库既有的 `ThumbCache.enabled` / `PreviewPlayer.enabled` 同构，改动面最小。代价是约 40 处 `const` 表达式必须去 const（编译期常量无法运行时变色），已逐处处理，没有改任何颜色值
		③ `app.dart`：`ref.watch(uiSettingsProvider)` 挂 `theme` / `darkTheme` / `themeMode`；`settings_service.dart` + `settings_provider.dart` 加 `appearance_mode` / `appearance_accent` 两个字符串 key 与 setter；`settings_screen.dart` 在 Display 之前新增 Appearance 分组：一行三态 `_seg`，一行 5 个色板 chip（每个带名字，选中态另有勾与当前强调色边框，窄屏 Wrap 换行），点选同帧生效、无重启无确认
		④ 页面级硬编码颜色全量主题化：10 个文件的深灰占位 / 面板 / AppBar / 空状态底色改读 token，其上的白色图标改墨色 token；`cloud_setup` 的 hint、`image_info_sheet` 的 hairline、标题栏 hover wash 等边界一并收掉
	3) 媒体 overlay 是唯一例外（已写进 DESIGN.md）
		① 播放器 chrome 渐变、查看器 scrim、filmstrip、卡片上盖在 poster/thumbnail 像素上的 badge 与时长标签，两种外观下都保持深色体系 + 白图标：它们是盖在未知画面上的墨层，不是页面表面，浅色控件在亮帧上会消失。QR 配对页是固定深蓝品牌世界，用 `Theme` 把继承的文字/图标钉回深色主题
	4) 文档与验证
		① `PRODUCT.md`：删废弃 `## Register`、补 schema stamp 与 Platform / Positioning / Operating Context / Capabilities / Brand Commitments / Evidence on Hand / Product Principles，更新因本功能过时的「只在昏暗环境」与「橙+深底是唯一选择」；只重组已确认事实，明确写出没有证言 / 定价 / 第三方基准
		② `DESIGN.md`：frontmatter 补 Day ramp，新增 §2A Appearances & Accents（双 ramp 表、5 色矩阵与对比度、入口与交互、媒体 overlay 例外），Overview / Info Dialogs / Do·Don't 同步
		③ 测试：`test/settings_appearance_test.dart` 新增 6 条（持久化往返与兜底、5 色唯一、两套 ThemeData、快照翻转、设置行写穿）；`settings_cache_entry_test.dart` / `settings_jump_history_slider_test.dart` 的视口高度加大——Appearance 把 Cache / Jump History 推到 ListView 折叠线外，是布局变化不是逻辑回归
		④ 门禁：`flutter analyze lib test` 零告警；全量 `flutter test` **745/745 全绿**（739 基线 + 6 条新增）。另按仓库惯例渲染 5 张 golden（Night / Day × 桌面 / 手机、换色、滚动到下半页）做成批视觉验收，发现并修掉「宽屏下色板被 `_group` 的 Column 居中、与上方 Theme 行不对齐」这一处，重渲染确认后停止打磨
		⑤ 未验证：无真机，Day 的真实屏幕观感与系统亮度实时切换未跑设备；`RCrmColors` 是进程级快照，若将来出现同进程内多 Theme 子树，需要改成 ThemeExtension

13. 2026.11.7.7.30.PM.Saturday
	*本批为未发布的工作区改动：视频页 Day 适配 / 窄屏三格按钮 / Material You 取色*

	1) 视频页的日间模式：媒体墨层必须有媒体垫底
		① 渲染证据（`.local_backup/render_out/video_day_grid.png`）：Day 下每张视频卡片底部是一条**黑渐变 + 白字**的信息带，右下角还有黑底白字的时长标签。它们本来是盖在海报像素上保证可读的 overlay，但海报未生成时盖在浅奶油占位块上，就成了「浅色卡片底部一条黑带」——这正是「视频页没适配日间模式」的来源
		② `VideoPoster` 新增 `onPosterChanged` 回调（postFrame 里通知，避免在子 widget 的 build / setState 中触发父级 setState）；`VideoCard` 用 `_hasPoster` 决定配色：有海报才画深色墨层 + 白字，占位时用 `RCrmColors.coal` 淡渐变 + `textPrimary` / `textSecondary` 文字，时长标签改用 `char` 底 + 主文字色。`didUpdateWidget` 换片时重置状态
		③ 设计原则写进 `DESIGN.md`：dark-on-content 是盖在**未知画面**上的墨层，不是页面表面；没有媒体时它没有理由存在。播放器 / 查看器的 overlay 仍按原例外保留
	2) 窄屏三格按钮换行
		① 320dp 渲染证据（`.local_backup/render_out/appearance_day_320.png`）：选中态默认的 ✓ 图标挤占 label 宽度，"System" 被压成两行；只撑满宽度 + `maxLines: 1` 会变成 "Sy…"，仍不完整
		② 窄屏 `_seg` 改为填满行宽、`VisualDensity.compact` + 6dp 水平内边距、关闭 `showSelectedIcon`（选中填充色本身已是状态信号），三个 label 加 `maxLines: 1` 兜底大型字号。重渲染确认 System / Day / Night 三个词都完整单行
	3) Android 12+ Material 3 系统取色
		① `pubspec.yaml` 加 `dynamic_color: ^2.1.0`（唯一新增依赖，传递引入 `material_color_utilities` 等）。`RcrmApp` 用 `DynamicColorBuilder` 包住 `MaterialApp`，在两次 ThemeData 构建前把 `lightDynamic.primary` / `darkDynamic.primary` 记进 `RCrmColors.setSystemColors`
		② `RCrmAccent` 增加第六个 `materialYou`（label `Device`），`RCrmTheme.primaryFor` 是 ThemeData 与运行时快照共用的唯一取值口；`onPrimaryFor` 按 `computeLuminance()` 实测决定黑/白文字，因为壁纸色没有已知明度
		③ **不能动作的控件不显示**：`Settings` 的色板只在 `RCrmColors.hasSystemColor`（两套动态 scheme 都在）时出现 Device，桌面 / iOS / 旧 Android 一律隐藏；取不到色时回落中性灰而不是凭空造一个主题色。PRODUCT.md 里原先「dynamic color 明确 out of scope」已改为已实现
	4) 验证与未验证
		① `flutter analyze lib test` 零告警；全量 `flutter test` **746/746 全绿**（745 + Material You 新增 1 条）；`settings_appearance_test.dart` 同步改为六预设并补系统色往返 / `onPrimary` 亮度判定
		② 视觉验收共渲染 6 张 appearance golden（新增 320dp）+ 3 张视频页 golden（Night / Day 网格 / Day 文件夹），一轮修完三项后重渲染确认
		③ 未验证：**没有 Android 12+ 真机**，Device 色板在真实壁纸色下的观感、系统亮度实时切换、以及 `DynamicColorBuilder` 首次异步返回 null 到带值之间是否有一帧回落，均需设备确认；桌面 / iOS 上该选项按设计隐藏，未做平台通道实测

14. 2026.11.8.2.10.AM.Sunday
	*本批为未发布的工作区改动：代码审查与修复（接第 12/13 条）*

	1) 审查方式与结论
		① 两个独立只读审查（主题架构与时序 / 页面主题化与媒体 overlay 例外）+ 自核对比度；共 5 条严重、6 条中等。架构本身成立（纯 ThemeData + builder 单点写入），真正的问题是**媒体世界误用了页面 token**：`RCrmColors` 全部自动跟随之后，播放器面板/菜单/Up next 卡片的底色 `ash`、进度轨道 `textDim`、强调色 `primary` 在 Day 下分别变成奶油、20% 黑、深橙——白字压在奶油面板上 1.23:1，轨道压在黑帧上 1.53:1
	2) 修复
		① 新增一组**固定媒体 token**（不随外观）：`mediaSurface`（面板/菜单/剧集 sheet）、`mediaAccent`（当前 accent 的 **Night** 变体，Day 的深变体在黑帧上太暗）、`mediaTrack`（20% 白）、`mediaText` / `mediaTextSecondary`、`mediaHairline`。播放器四个文件 + 剧集面板 + 查看器顶栏全部切过去
		② 查看器顶栏是**确定误改**（浮在黑 scrim 上的文件名用了 Day 墨色，1.17:1），回到 `mediaText` / `mediaTextSecondary`
		③ `hairline` 新 token（Night 8% 白 / Day 8% 墨）：`desktop_title_bar` 与 `image_info_sheet` 之前被换成 `textDim`（20%），细线变粗线
		④ 状态色 `ok` / `warn` / `bad`（Night 用 Material 绿/橙/红 500，Day 用 `#1B5E20` / `#8A5A00` / `#C62828`）：`doctor_panel` 原来的 `Colors.green/orange/red` 在奶油底上只有 1.7–3.0:1
		⑤ `outline` 从 `dim`（1.35–1.55:1）改为 `textFaint`（4.9–5.0:1）；accent chip 未选中边框、服务器停止态圆点同样改 `textFaint`
		⑥ **`hasSystemColor` 加 `Platform.isAndroid`**：`dynamic_color` 的包文档明写 macOS / Windows / Linux 也会用系统强调色构造 scheme，原实现会让桌面出现 Device 色板、甚至把品牌色换成系统蓝，与「只在 Android 提供」不符
		⑦ `RcrmApp` 的 `ref.watch` 收窄为 `select((s) => (s.appearanceMode, s.appearanceAccent))`（原写法任何设置变更都会重造两份 ThemeData）；`themeAnimationDuration: Duration.zero`——`AnimatedTheme` 的 200ms 插值会在中点翻转 `ColorScheme.brightness`，而 `RCrmColors` 只能持有一个世界，中点会出现「半奶油底 + 白字」
		⑧ `VideoPoster._notify` 捕获 `_gen` 再比对（元素复用到另一条视频后，上一代的 `true` 不会落到新元素上）；`didUpdateWidget` 改为先 `_load()`（同步递增 `_gen`）再通知 `false`
	3) 验证与未验证
		① `flutter analyze lib test` 零告警；全量 `flutter test` **746/746 全绿**（未新增用例；`settings_appearance_test.dart` 改了一条断言——`hasSystemColor` 现在有 Android 门，桌面测试宿主上恒为 false，恰好证明平台限制生效）
		② 未修（记录在案）：`hasSystemColor` 无通知机制——Android 上动态色回包时若当前不是 Device，设置页不会自动长出 Device 色板（下次重建才出现）；存了 Device 但平台不提供动态色时回落中性灰且色板无选中项；`_hasPoster` 在海报到达前有一帧浅色信息带（Night 从纯黑变成 coal）；`dynamic_color` 传递引入 `intl` 等 4 个包

15. 2026.11.8.5.10.AM.Sunday
	*本批为未发布的工作区改动：视频播放页跟随外观（修正第 14 条的判断）*

	1) 判断纠正：播放页不是浮层，是页面
		① 第 14 条把播放器归入「固定深色媒体世界」，用户明确否决：「视频播放页要跟随日间主体，不能依旧黑」。该归类是错的——播放器占满整条路由、用户在其中停留很久，它不是盖在内容上的徽标
		② 渲染证据：Day 下 `Scaffold(backgroundColor: Colors.black)` 让页面四周仍是黑边，控制条渐变仍是黑，面板又刚被改成固定深色，与浅色库完全割裂
	2) 实现
		① `video_player_screen`：两处 `Scaffold(backgroundColor: Colors.black)` → `RCrmColors.pitch`
		② 播放器 4 个文件 + 剧集面板：前景 `Colors.white*` 全改语义（`textPrimary` / `textSecondary` / `textFaint`），底色 `mediaSurface` → `ash`，accent 改 `primary`，轨道改 `textDim`，hairline 改 `hairline`，分段选中文字 `Colors.black` → `onPrimary`
		③ 新增 `playerScrim` / `playerScrimStrong`（随外观：Night `0x80000000` / `0xB3000000`，Day `0xCCF6F1E9` / `0xE6F6F1E9`）。**渐变终点必须是同色零透明** `playerScrim.withValues(alpha: 0)`，不能用 `Colors.transparent`——后者是黑色透明，奶油起点会经过深灰插值，墨字正好落在暗带上；首轮渲染就是这么错的，看图才发现
		④ 删除已无使用者的 `mediaSurface` / `mediaAccent` / `mediaTrack` / `mediaHairline`；只保留 `mediaText` / `mediaTextSecondary` 给图片查看器顶栏（白字压在照片的黑 scrim 上）
		⑤ `_iconButton` 的 `Color color = RCrmColors.textFaint` 默认值改成 `Color? color` + 内部 `?? textFaint`（可选参数默认值必须是编译期常量）
		⑥ 其余压在画面上的表面一并跟随：缓冲 spinner 圆底、设置面板 backdrop、剧集 sheet backdrop、手势 2x chip、Up next scrim 改 `pitch` / `char` 语义色
	3) 验证与未验证
		① `flutter analyze lib test` 零告警；全量 `flutter test` **746/746 全绿**
		② 渲染验收：控制条 Day/Night、播放设置面板 Day/Night（面板在 Day 下浅底墨字、分段选中深橙底白字、图标可见）；控制条 Day 下浅渐变 + 深色图标与时间 + 橙色进度
		③ 未验证：无真机；剧集 sheet 的独立渲染探针因布局异常未出图，但该面板只做了配色替换，构建由全量测试覆盖；PiP 浮窗仍保持黑底（它是视频容器，浮在库页面之上，不属于播放页）

16. 2026.11.8.11.30.AM.Sunday
	*本批为未发布的工作区改动：播放页可见性修复（用户真机截图反馈）*

	1) 用户截图指出：Related 列表的文件名、播放器下方的大号视频标题全是白字压奶油底，控制条时间发灰，「完全背景和字体不可视」。第 15 条的验收图只覆盖了独立的控制条与设置面板，没覆盖这个整页，属于验收盲区
	2) 根因：第 15 条只检查并改了 `widgets/player_*` 四个文件，**漏了 `screens/video_player_screen.dart` 自身**。它的 `_meta()`（标题 / 时长 / 大小 / 扩展名 / Divider）、`_related()` 的标题与每个列表项、以及窗口与全屏两套 Related 标题，共 13 处仍是 `Colors.white / white54 / white70 / white12`；另有 2 处 `Color(0xFFFF6B00)` 与 2 处手势 HUD 进度色写死
	3) 修复
		① 13 处页面级前景改 `textPrimary` / `textSecondary` / `hairline`，4 处硬编码橙改 `RCrmColors.primary`；对应 `const` 逐处去掉
		② Day 的 `playerScrim` 从 80% 提到 96%：控件位于渐变约 1/3 处，80% 起点到那里只剩约 56% 奶油，墨字压在中灰上发灰。新增 `playerScrimMid`（Night 40% 黑 / Day 92% 奶油）配合 `stops [0, 0.65, 1]`，让控件行整段保持实色
		③ 对比度实测（Day）：`textPrimary` on pitch 15.99:1、`textSecondary` 6.70:1、`textPrimary` on 96% scrim 15.57:1
	4) 保留：全屏顶栏三个 `white70` 图标（叠在视频画面上、没有页面底）、手势 seek HUD 的白字与 20% 白轨道、PiP 浮窗黑底
	5) 验证：`flutter analyze lib test` 零告警；全量 `flutter test` **746/746 全绿**；重渲染控制条 Day/Night，Day 为浅奶油底 + 深墨图标时间 + 橙色进度
	6) 未验证：无真机，未复现用户截图的完整播放页（`_meta` / `_related` 是私有方法，widget 探针只覆盖了控制条与面板）；全屏顶栏白图标在亮画面上的可读性仍需设备确认

17. 2026.11.8.11.50.AM.Sunday
	*本批为未发布的工作区改动：播放器控件上下渐变恢复固定暗色（用户第二次截图纠正）*

	1) 用户明确：「视频播放器控件上下的白边不要跟日夜间模式走，就原来那样的（默认的暗色模式的），也不要补充白边的长宽」
		① 第 15 条把控制条与顶栏渐变改成奶油色，第 16 条又为可读性把不透明度 80%→96% 并加 `playerScrimMid` + `stops [0, 0.65, 1]`，等于给白边加厚——两个决定都否掉
		② 正确边界：**播放页的页面部分跟随外观**（Scaffold / 大标题 / meta / Related），**浮在画面上的控件不跟随**（上下渐变、倍速与模式菜单、播放设置面板、剧集 sheet）
	2) 实现
		① `config/theme.dart`：`playerScrim` / `playerScrimStrong` 回到固定 `0x80000000` / `0xB3000000`，删除 `playerScrimMid` 与所有 appearance 分支；新增固定的 `playerText` / `playerTextSecondary` / `playerTextFaint` / `playerTrack` / `playerHairline` / `playerSurface` / `playerAccent`
		② `playerAccent` 仍跟主题色，但取所选色的 **Night（亮）变体**，压在黑底上可读；取不到才回落 Marquee
		③ 五个播放器 widget 文件批量切回固定 token；手势 chip、backdrop、缓冲圆底、未选中段底恢复原来的黑色半透明，选中段文字恢复近黑
		④ 渐变恢复**两色无 stops**，不补任何长度或宽度；终点仍是同色零透明（避免 `Colors.transparent` 的黑插值）
		⑤ 页面部分**未回退**：`video_player_screen.dart` 的 `_meta()` / `_related()` / Scaffold 仍用语义色，第 16 条修好的白字问题保持
	3) 验证：`flutter analyze lib test` 零告警；全量 `flutter test` **745 通过 + 1 条环境超时**（`media_metadata_test.dart` 的 30s 超时，单独重跑 19/19 通过；当时并行跑着 analyze + 两次渲染 + 全量测试，C 盘 95%）；重渲染 Day/Night 控制条与设置面板，Day 与 Night 一致（深色渐变 + 白字，无奶油边、无加厚）
	4) 文档：DESIGN.md 改为「a themed page with fixed dark chrome」，PRODUCT.md 同步

18. 2026.11.13.2.40.AM.Friday
	*本批为未发布的工作区改动：Flutter 3.50 / Dart 3.14 一次性迁移与版本锁*

	1) 提交顺序：先把暂存区（缩略图缓存修复 + Cargo.lock，8 文件）提交为 `594c867`，再把工作区（主题三层 + 播放器 chrome + 文档，38 文件）提交为 `767e2dc`。两次提交后工作区干净，才开始迁移
	2) `dart fix --apply`（本机 Flutter 3.50.0 / Dart 3.14.0）
		① 84 个 fix / 83 文件：82 个 `deprecated_member_use` 把 `package:flutter/material.dart` 换成官方 `package:material_ui/material_ui.dart`——Material 库在 3.47+ 从 Flutter 拆出（包来自 `flutter/packages`，要求 Flutter ≥3.47）；1 个 `missing_dependency` 在 `pubspec.yaml` 加 `material_ui`；1 个 `unnecessary_import` 删掉 `image_grid.dart` 里 `flutter/rendering.dart` 的 `ScrollCacheExtent`
		② `flutter analyze lib test` 零告警；`flutter pub get` 顺带解析出 4 个依赖升级（test 1.31.1 → 1.32.0 等）
	3) 版本锁（一次性）
		① `pubspec.yaml`：`environment.sdk` 从 `^3.12.2` 提到 `">=3.14.0 <4.0.0"`，新增 `flutter: ">=3.50.0"`；`material_ui: any` 收紧为 `^1.10.0`
		② `pubspec.lock`：`sdks.dart` / `sdks.flutter` 同步为 `">=3.14.0 <4.0.0"` / `">=3.50.0"`
		③ `docs/BUILDING.md`：版本矩阵改 3.50.0 / Dart 3.14.0；Prerequisites 改 ≥3.50 并写明 material_ui import 规则；Impeller 段改为「3.47+ 包括 3.50」并注明本次未重跑 Windows 解码验证
		④ 本地 `AGENTS.md`（gitignored，不进版本库）：更新版本约束行、Impeller 描述，以及「`SliderThemeData.padding` 是 3.47-only 而本仓库 floor 是 3.44」这条**已失效的理由**（现在 floor 3.50，改述为几何已单元测试、换 inset 模型会改变映射）
	4) 验证：`flutter analyze lib test` 零告警；全量 `flutter test` **746/746 全绿**
	5) 未验证：未跑 Windows / Android 真机构建；Impeller 的 AVIF/JXL/HEIC 解码问题在 3.50 下未重新验证，文档按「仍存在」处理

19. 2026.11.13.3.5.AM.Friday
	*本批为未发布的工作区改动：Flutter 3.50 Android 构建链修复、Linux 回归审查、window_manager 升级决策*

	1) 触发：`flutter build apk` 在 `app/build.gradle.kts:1` 应用 `dev.flutter.flutter-gradle-plugin` 时硬失败 —— Gradle 9.1.0 低于 Flutter 最低 9.3.1。第 18 条只迁移了 Dart 侧（`dart fix` + 版本锁），Android 模板未同步，这是留下的缺口
	2) 取证（版本不从二手文档抄，读本机 SDK 源码）
		① `D:\Dev\flutter\packages\flutter_tools\gradle\src\main\kotlin\DependencyVersionChecker.kt`：error 阈值 Gradle 9.3.1 / AGP 9.1.1 / KGP 2.4.10 / Java 17 / minSdk 23；warn 阈值 9.5.0 / 9.3.1 / 2.4.20
		② `gradle_utils.dart` `validateGradleAndAgp`：AGP 9.1.x 需 Gradle ≥9.3.1（9.2.x ≥9.4.1，9.3.x ≥9.5.0），三者必须联动
		③ Flutter 自带 included build 的 `compileOnly` 目标正是 AGP 9.1.1 / KGP 2.4.10，因此取「最低值」比模板默认（9.5.0 / 9.3.1 / 2.4.20）更稳
		④ 镜像预检：腾讯 `gradle-9.3.1-all.zip` 200（234,893,460 B）、阿里云 AGP 9.1.1 POM 200、KGP 2.4.10 marker POM 200
	3) 修改
		① `android/gradle/wrapper/gradle-wrapper.properties` 9.1.0 → 9.3.1（保留腾讯镜像 URL）；`android/settings.gradle.kts` AGP 9.0.1 → 9.1.1、KGP 2.3.20 → 2.4.10；两处都加注释说明联动关系
		② 不用 `--android-skip-build-dependency-validation`：那只是绕过检查，不是修复
		③ 核实 `injectGradleWrapperIfNeeded` 仅在 properties 缺失时写入，手改的镜像 URL 不会被 SDK 覆盖
	4) Android 验证
		① `android/gradlew :app:tasks --no-daemon` 从零下载 Gradle 9.3.1 后 **BUILD SUCCESSFUL in 2m 12s**，原报错的配置阶段已通过
		② 复跑 `gradlew help` 捕获 3 条预期 warn：Gradle ≥9.5.0 / AGP ≥9.3.1 / Kotlin ≥2.4.20 的「will soon be dropped」，均非致命（BUILD SUCCESSFUL in 35s）。文档写明不要把 warn 当错误，也不为消 warn 冒进模板默认版
	5) Linux 3.50 C++ 异常回归（用户点名的硬性阻碍）排查结论
		① 回归内容：引擎导出 `_Unwind_*`，Linux 插件中的 C++ `try/catch` 捕获不到异常 → SIGABRT；典型受害是 `flutter_secure_storage_linux`，3.47.9 无此问题
		② 静态审查本机 pub cache：`generated_plugin_registrant.cc` 注册的 5 个 Linux 原生插件（dynamic_color / media_kit_libs_linux / media_kit_video / screen_retriever_linux / window_manager 0.5.2）的 `linux/` 源码 **0 处 try/catch**；`pubspec.lock` 无 flutter_secure_storage；`linux/runner/*.cc` 无 C++ 异常。**当前不受影响**
		③ 未验证：Rust bridge 静态链接的 zxing-cpp（C++）在 Linux 是否有跨边界抛异常、media_kit_libs_linux 的预编译 libmpv .so —— 本机为 Windows，无 Linux 构建环境，须在 Linux 分支实测启动
		④ 保留规则：新增/升级 Linux 插件前先 grep 其 `linux/` 的 C++ `try`/`catch`，命中就在 Linux 分支验证 3.50 启动；Windows CI 全绿不能证明 unwind 正常
	6) `window_manager` 0.7.0：评估后**不升级**（`flutter pub outdated` 仍会提示 0.7.0 available，属预期）
		① 0.6/0.7 是破坏性重写：0.5.x API 移到 `package:window_manager/legacy.dart` 且全部 `@Deprecated`（会破坏 analyze 零告警门禁）；新 API 为 `WindowManager.instance.getCurrent()` + 事件流，约 30 处调用点要改
		② 更关键：它删掉全部平台插件代码，改由 `nativeapi` / `cnativeapi` 一个 C++ core（Dart build hook 从源码编进 Linux app）。`cnativeapi` 0.6.0 约 70 个 C++ 文件用 try/catch，含 `src/platform/linux/secure_storage_linux.cpp` 与全部 C-ABI wrapper —— **升级等于主动引入第 5 条那个回归**
		③ 另需 material_ui ^1.11.0、nativeapi(–flutter) ^0.6.0、Linux 构建机 GTK3/X11/Xi 开发头（`scripts/build_linux.sh` 未装）
		④ `^0.5.2` 本就排除 0.6+/0.7+，`flutter pub upgrade` 不会误带入；在 `pubspec.yaml` 写明故意停留的原因，并在 BUILDING.md 留四步迁移清单
	7) 文档：`docs/BUILDING.md` 版本矩阵改 9.3.1 / 9.1.1 / 2.4.10，新增 3.50 error/warn 阈值表、再次升级步骤（含镜像预检）、新章「Flutter 3.50 Linux regression」、Android 排错表新增该报错；`AGENTS.md`（gitignored，本地）同步版本 pins 与两条新约束
	8) 门禁：`flutter analyze lib test` 零告警；`flutter test` **746/746 全绿**（清代理 + 新 TEMP）；`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿
	9) 未验证：未跑 Android 真机 / APK 打包（只验到 Gradle 配置阶段，未编译 Kotlin 与 JNI 产物）；未跑 Windows / Linux 桌面构建；Linux 回归缺实机启动验证；`pubspec.lock` 沿用第 18 条遗留下的未提交依赖解析，`flutter pub get` 后保持 `dart >=3.14.0 <4.0.0` / `flutter >=3.50.0`

20. 2026.11.13.3.12.AM.Friday
	*本批为对第 19 条配置期警告的追问与实测（无构建配置改动）*

	1) 用户跑 `./gradlew help` 后质疑「这不对吧」：输出里有 3 条 Flutter `will soon be dropped`（还带 `--android-skip-build-dependency-validation` 与 "Potential fix"）、2 条 AGP 的 `android.builtInKotlin=false` / `android.newDsl=false` deprecated、1 条 KGP 的 `org.jetbrains.kotlin.android` 不再需要；而且「请把 Kotlin 升到 2.4.20」和「不需要 KGP 插件」并排出现，看着自相矛盾
	2) 查证结论（**全是警告，配置阶段 BUILD SUCCESSFUL**）
		① `DependencyVersionChecker.kt` 里 `getWarnMessage` 与 `getErrorMessage` **共用同一段模板串**，所以 warn 也带 bypass flag 与 Potential fix —— 纯文案误导，不是错误，更不该加那个 flag。我们停在 error 阈值（9.3.1 / 9.1.1 / 2.4.10），warn 阈值高一档（9.5.0 / 9.3.1 / 2.4.20），是 Flutter 提前一个版本的预告
		② **Flutter 3.50 官方模板 `templates/app/android.tmpl/gradle.properties.tmpl` 第 3–6 行自己就写 `android.newDsl=false` + `android.builtInKotlin=false`**，`settings.gradle.kts.tmpl` 第 23 行仍声明 KGP 插件。不是 3.44/3.47 遗留，也不是版本升级改坏的；Flutter 的 AGP 9 newDsl / 内置 Kotlin 迁移仍在进行（flutter/flutter#180137）
		③ 矛盾来源：`FlutterPluginUtils.isBuiltInKotlinEnabled` 读 `android.builtInKotlin`，显式 false 让 Flutter 判定「未启用内置 Kotlin」→ 仍按独立 KGP 检查版本并打 warn；AGP/KGP 那边则说独立 KGP 已废弃。两套机制各说各的
	3) 实测（不改文件，命令行覆盖：`./gradlew help --no-daemon -Pandroid.builtInKotlin=true -Pandroid.newDsl=true`）
		① **BUILD SUCCESSFUL in 45s**；2 条 AGP deprecated、1 条 KGP obsolete、1 条 KGP 版本 warn 全部消失，只剩 2 条 Flutter 版本 warn；另冒出 `screen_brightness_android` 的 2 条 `srcDirs` deprecated
		② 但 `help` 只做配置，不编译 Kotlin、不打包 APK。`android_file_picker` 2.1.6 的 `build.gradle.kts` 明确为 `android.newDsl=false` 项目保留 AGP 8.5.2 / KGP 1.8.22 的 buildscript classpath，注释写明「等上游迁移落地、不再需要 `android.newDsl=false` 时再删」——**保留模板开关**，不为了消警告动它
		③ 升到 warn 阈值可消掉剩余 2 条，但 AGP 9.3.1 高于 included build 的 `compileOnly` 目标 9.1.1，三件套要一起动；而且**消不掉**那 2 条 AGP deprecated（它们来自 `gradle.properties`，与版本号无关）
	4) 文档：`docs/BUILDING.md` 新增「Configuration-time warnings under Flutter 3.50」章节（三类来源表、文案误导说明、实测记录、不要动 flag 的理由）；`AGENTS.md` 同步一行速查
	5) 本批**未改动任何构建配置文件**。未跑 `assembleDebug` / APK 打包，内置 Kotlin 下的 Kotlin 编译链仍未验证；若将来要迁，需先跑一次完整 assemble 再动 `gradle.properties`

22. 2026.11.13.5.10.AM.Friday
	*本批为未发布的工作区改动：视频完播（end-of-playback）界面*

	1) 用户给了一张 B 站播放结束页截图，要求「参考可取元素做完播 playback」。先做取舍审查，不照抄
	2) 可取（已实现）：完播即在画面上给出下一步；一行「图标 + 文字」动作（重播 / 下一个 / 全部）；相关推荐缩略图网格 + 时长角标；合集入口带数量；压暗的最后一帧作背景
	3) 不可取（明确拒绝）：模糊 / 玻璃背景（DESIGN.md §6 明禁 glassmorphism）；作者条 / 关注 / 充电 / 投币 / 点赞 / 弹幕 / 广告（本地加密媒体库没有社交语义）；蓝色主按钮与网站导航 / 侧栏
	4) 现状缺口（先查代码再动手）：`pauseAfter`（默认模式）完播后只有静止最后一帧 + 自动淡出的控制条，全屏时没有重播、没有下一个、也回不到 Related；`loopAll` / `shuffle` 在 Related 为空时同样什么都没有。原 8 秒 Up next 卡片只在 `offersNextVideo` 且真的有下一个时出现
	5) 实现
		① 新增 `widgets/player_end_card.dart`：`playerSurface` 卡片 + `playerScrim` 压暗；标题 `Playback finished` + 文件名；动作行 Replay / Play next（accent）/ All N；Related 2×3 网格（`VideoPoster` + 时长角标 + 两行标题）；✕ 与背景点击同义
		② 网格列数按宽度（≥560dp 三列，否则两列），**行数按卡片真实可用高度**（`LayoutBuilder` 的 `bounds.maxHeight`，不是屏幕高度）：420dp 横屏只放一行，避免第二行被裁成半截；卡片限高同样用 `bounds.maxHeight`，窗口模式的 16:9 画面框不会让卡片溢出画面
		③ 互斥与既有语义：完播卡片只在 `_eof.finished && _upNext == null && !_endingChoiceDismissed` 时出现；`loopAll` / `shuffle` 的 8 秒倒计时卡片原样保留；✕ 关掉任一卡片都会置 `_endingChoiceDismissed`，新一次 ending 才复位 —— 保住「✕ = 停在最后一帧」的承诺。**这里的「互斥」是错的，已由第 24 条替换：完播卡片本身就是 Up next 的载体。**
		④ `All N` 只在全屏传入（剧集 sheet 只挂在全屏分支；窗口模式右侧已有完整 Related，按钮会是死控件）
		⑤ 重播走 `seek(0) + play()` 并把 `_eof` 置回 idle；点推荐走 `_playInPlace(back: false)` 与 Next 同一路径，不新增路由语义
		⑥ 入场 200ms / 退场 140ms，`disableAnimations` 直接切状态；橙色只出现在 `Play next` 与 Related 小圆点
	6) 验证
		① 新增 `test/player_end_card_test.dart` 8 例：动作回调、空 Related、无 sheet 时按钮缺席、网格 3×2 上限、点卡片、✕ 回调一次、背景点击、reduced motion
		② 渲染验收（`.local_backup/render_end_card_test.dart`，真字体出 PNG）：1280×800 宽屏、800×420 横屏、空态、Day 窗口模式、超长标题五张；首轮发现横屏第二行被裁，按高度算行数后复渲染确认
		③ 期间修了探针自身的一个坑：测试里用空 `MediaQueryData()` 覆盖会丢失 `size`，导致卡片限高被 clamp 到 180、内容被裁 —— 不是组件问题；同时把卡片限高从 `MediaQuery.sizeOf` 改为 `LayoutBuilder` 的 `bounds.maxHeight`
		④ `flutter analyze lib test` 零告警；新增 8 例全绿
	7) 未验证：没有真机 / 桌面实际播放到结尾的验收（完播触发依赖真实 `completed` 事件）；海报在真实库中的加载与缓存表现未在本轮渲染（探针抑制了生成，全是占位）；未测平板竖屏等中间尺寸
	8) 文档：DESIGN.md 在 Controls Overlay 增加 End card 条目（含「不是模糊流媒体结束页」的边界）

23. 2026.11.13.5.15.AM.Friday
	*本批为未发布的工作区改动：列表式视频卡片的缩略图比例修复*

	1) 用户反馈「横屏列表样式的视频卡片会被压缩得很难看，比例极端」。定位：`VideoListTile`（视频 tab 列表 + 搜索结果列表）的缩略图用 `Expanded(flex: 2)`，宽度随窗口增长 —— 1600dp 宽时是 630×100（6.3:1），`BoxFit.cover` 把 16:9 海报裁成一条横带。播放页 `_relItem` 同样是 flex 2/5：380dp 侧栏下恰好接近 16:9，但平板 / 手机全宽的 Related 会到 3.6:1
	2) 修复：两处都把缩略图宽度改为 `min(行高 × 16/9, 可用宽度 × 0.42)` —— 横屏锁在 16:9，窄屏允许缩小给文字列让位，**永不随窗口变宽**。行高不变（列表 100dp / Related 90dp）
	3) 验证：渲染探针（`.local_backup/render_video_list_test.dart`，真字体）在 1600 / 360 / 820 三档出图，宽屏从 630×100 变为 178×100；新增 `test/video_list_tile_test.dart` 3 例钉住「宽屏 16:9」「窄屏收缩」「文字列仍拿到剩余宽度」
	4) 注意：测试 VM 用 Ahem 字体，两行标题在 100dp 行内会溢出 14px（真字体渲染图正常），所以测试用短标题、只断言几何；带 textScale 的大字号场景未验证
	5) 门禁：`flutter analyze lib test` 零告警、全量 `flutter test` 全绿、cargo 门禁全绿

21. 2026.11.13.3.30.AM.Friday
	*本批为未发布的工作区改动：Flutter 3.50 直接原生互操作审查 + 平台通道类型化重写*

	1) 用户要求：审查「FFIgen/JNIgen stable、Pigeon native interop preview」这段升级说明，并依此对全部桥接能力做进化性重写
	2) 审查结论（先纠正转述，再决定动作）
		① 官方博客原话是「FFIgen for Objective-C 和 JNIgen 加入 **FFIgen's long-standing C support** 一起 stable」—— **C 支持早就 stable**，3.50 新增的是 ObjC 绑定与 JNIgen。本项目是纯 C ABI，没有新增能力可用
		② 「不再有序列化开销」不严谨：Pigeon 官方对比表写明 data classes / List / Map 仍是 **per-call 一次 buffer 编码**（29.2.0 才优化成单 buffer）；只有标量、字符串、枚举、typed data 直传
		③ 「过去 Dart 调原生走 Platform Channel、强制异步」只描述平台通道；`dart:ffi` 一直可同步、可从任意 isolate 调用，本项目 25 个 Rust 导出一直是这条路
		④ Pigeon native interop 的 iOS/macOS/Android 范围说对了，但它是 **Preview**（29.0.0 experimental → 29.1.1 Preview → 30.0.0 BREAKING CHANGE），且**明确不支持 Windows/Linux**；官方另列多引擎路由、后台 isolate 无 engineId、`@FlutterApi` hot restart 残留、macOS 无 detach 回调等限制
		⑤ 口径冲突：Flutter 博客宣布 stable，dart.dev 的 Java interop 页仍标 **experimental**；pub.dev `jnigen` 已是 1.0.1（早于 3.50 发布 42 天），无 status 标签
		⑥ 工具链前置：`ffigen` 23.0.0 需 LLVM ≥18（本机 MSYS2 有 23.1.5 + `libclang.dll`）、只解析 C 头（不支持 C++）、YAML 配置已弃用；`jnigen` 需 JDK 17–21 + CMake + Gradle stub，Android SDK stubs >28 不完整；Pigeon native interop 官方自评 "Setup Complexity: Complex"
	3) 现状盘点：**25 个** Rust C-ABI 导出（手写 `dart:ffi`，7 个 lib 文件、3 个 Struct 镜像、2 个 `NativeCallable.listener`）＋ **7 个** MethodChannel / **11 个**方法（6 个 Android、3 个 iOS 半边、1 个 Windows；1 个原生→Dart 推送 `onChanged`）＋ **0** 代码生成框架
	4) 逐点判定：**全量替换是负收益**
		① Rust 主桥接不迁：`ffigen` 只生成签名，表达不了 4 种所有权形状、len-only `Vec::from_raw_parts`、超时不得释放、feature-gated 符号的运行时探测、`NativeFinalizer` 地址与 listener 回调；还要求新增并维护一份 `.h`
		② Android/iOS 通道不迁：本质是 Activity/Context、BroadcastReceiver + ContentObserver、AVAudioSession 的生命周期封装，不是「Dart 调 Java 类」；`onChanged` 正是 Pigeon `@FlutterApi` 风险最高的路径
		③ Windows `rcrm/window` 不迁：一个无参 void 命令，序列化开销为零；改成 FFI 会失去 runner 持有的真实 `HWND`
		④ 第三方插件（camera / media_kit / window_manager 等）的通道不可改
	5) 实际重写：引文里另一半「string-based plumbing」才是可落地的进化
		① 新增 `lib/services/platform_bridge.dart`：`PlatformChannelNames`（7）、`PlatformMethods`（10 个 Dart→原生 + 1 个原生→Dart）、`PlatformArgs`、`PlatformBridge`（7 个 `const MethodChannel` + 类型化调用 + `reply()` 把 untyped 回包规范成 `Map<String,Object?>` + `watchVolumeChanges` / `stopWatchingVolumeChanges` / `exitApp`）
		② 7 个 service 全部改为调用类型层：`tv_detector` / `screen_capture` / `screen_orientation` / `storage_access` / `system_volume`（删掉 `_call(String method, [Object? args])`，改为 `_call(Future<Map<String,Object?>?> Function())`）/ `window_drag` / `double_back_exit`；保留 `ScreenOrientation.channel` 与 `SystemVolume.channel` 公开别名（测试依赖）
		③ **线上行为零变化**：channel 名、方法名、StandardMessageCodec 载荷、异常与 fallback 策略全部不变 → Kotlin / Swift / Windows runner 与既有 mock 测试无需改动
		④ 新增 `test/platform_bridge_test.dart` 13 例：钉住 7 个通道名 + 11 个方法名 + 参数键、回包规范化、各类型化调用发出的 method/arguments、`onChanged` 过滤与注销
	6) 文档：`docs/API_REFERENCE.md` 新增「Native interop review (Flutter 3.50)」（已是直接互操作的证据、三工具不迁的逐条理由、类型化边界与未来迁移路径）；`AGENTS.md` Must-Know 新增一条「不要在 `platform_bridge.dart` 之外写 `invokeMethod` 字符串」
	7) 门禁：`flutter analyze lib test` 零告警；`flutter test` **759/759 全绿**（746 + 新增 13）；`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿。Rust 侧本批未改
	8) 未验证：未跑 Android / iOS / Windows 真机构建（线上行为靠「wire 不变 + mock 测试」保证，不是设备验证）；未引入 `ffigen` / `jnigen` / `pigeon` 依赖（本机 LLVM 23.1.5 可用，但审查判定无收益）

22. 2026.11.13.3.55.AM.Friday
	*本批为未发布的工作区改动：Android 工具链一次性跳到 Gradle 9.9.1 / AGP 9.3.1 / KGP 2.4.21*

	1) 触发：用户贴出 3 条 `will soon be dropped`，要求直接升 Gradle 9.9.1，再追问 AGP / Kotlin、KGP 2.4.21
	2) 取证：`DependencyVersionChecker.kt` 只判下限（error 9.3.1 / 9.1.1 / 2.4.10，warn 9.5.0 / 9.3.1 / 2.4.20）；Kotlin 官方 KGP 2.4.20–2.4.21 完全支持 Gradle ≤9.7.0 / AGP ≤9.3.1；AGP 9.3 → Gradle ≥9.5.0、9.4/9.5 → ≥9.6.0；腾讯 Gradle zip 与阿里云 AGP/KGP POM 全 200
	3) 版本选择：AGP 9.3.1（模板默认 + KGP 支持上限），不用 9.5.0（离 included build 的 compileOnly 9.1.1 / 2.4.10 太远）；KGP 2.4.21 与 2.4.20 同兼容区间，且 SDK 对 >2.4.20 的 KGP 走「未知版本视为有效」分支 → `--suggestions` 少报一条 `Incompatible KGP/Gradle versions`
	4) 三步实测（每步完整 `flutter build apk --release`）：只升 Gradle → APK 125.7MB / 363.8s（`:app:tasks` 3m40s）；+AGP 9.3.1 / KGP 2.4.20 → 350.2s；换 2.4.21 → 223.9s，3 条 warn 全消
	5) 审查发现：`./gradlew help` BUILD SUCCESSFUL 1m9s，仍有模板 flags deprecated、AGP 9.3.1 新增 4 条 Variant API obsolete、KGP obsolete、Gradle 9.9 的 Kotlin DSL `w:` 与 javac 8 警告，全部非致命，不动模板开关；`--suggestions` 仅剩 1 条 `Incompatible Gradle/AGP versions`（AGP 9.3.x 上限写死 9.5.0，只喂诊断）
	6) 门禁：`flutter analyze lib test` 零告警；`flutter test` 759/759；`cargo build --locked`；`cargo test -- --skip compare_` 全绿
	7) 文档：BUILDING.md 版本矩阵与三个章节、AGENTS.md（gitignored）、本条 CHANGELOG；本地 memory 同步
	8) 未验证：无 Android 真机安装 / 启动；`--suggestions` 那条诊断未消除（需等 SDK 抬高上限）；未跑桌面构建

24. 2026.11.13.5.30.AM.Friday
	*本批为第 22 条（完播界面）的修正：完播卡片就是 Up next 的替代，不是与它互斥*

	1) 用户指出：参考图第一张推荐卡上有转圈等待自动跳转 + 「取消连播」，说明 B 站的结束页本身承载了 Up next；第 22 条把两者做成互斥是错的
	2) 重构
		① `PlayerEndCard` 新增 `autoPlayItem` / `autoPlayShuffled` / `countdown` / `onAutoPlay` / `onCancelAutoPlay`：倒计时环画在**第一张推荐卡**上（即使 offer 在 Related 里不是第一条，也前置到第一格），海报压暗 + 中央 40px 环 + 左上 `Cancel` chip
		② 标题区加一行 `Random pick · auto-plays in 8s`（shuffle 说明来源），取消后消失
		③ 动作行删掉 `Play next`：第一张卡就是「立即播放」，不再有两个门到同一个视频
		④ 删除 `PlayerUpNextCard` 与 `_upNextCard()`、`_dismissUpNext()`、`_barClearance()`；`player_overlays.dart` 回到只有 buffering + error 两个 overlay
		⑤ 显示条件改为 `_eof.finished && !_endingChoiceDismissed`：有 offer 时卡片带环，无 offer（`pauseAfter` / Related 空）时同一张卡不带环，不再有第二个浮层
		⑥ 语义保留：8 秒、点第一张卡立即播、`Cancel` 只停表保留卡片、✕ / 背景关闭卡片并停表、take-back 与模式切换仍 `_clearUpNext()`、每次 ending 只决定一次
	3) 测试：`player_end_card_test.dart` 11 例（新增 offer 前置 / 环 / `Cancel` / 倒计时只触发一次 / 撤下 offer 停表）；`player_overlays_test.dart` 删除 UpNextCard 组，保留 buffering / error
	4) 渲染：`.local_backup/render_end_card_test.dart` 新增 `end_card_autoplay`，确认第一张卡压暗 + 橙环 + `Cancel`，且 offer 不在列表首位时被提到第一格
	5) 门禁：`flutter analyze lib test` 零告警、全量 `flutter test` 全绿、cargo 门禁全绿
	6) 未验证：真机播放到结尾的实际自动跳转；`Cancel` 后切后台再回来是否仍保持取消（screen 状态在，理论保持）

25. 2026.11.13.12.30.PM.Friday
	*本批为完播卡片的 hover 预览补齐*

	1) 用户指出新做的完播卡片没有 hover play。原因：格子用的是 `VideoPoster`（纯海报），而播放页 Related 行用的是 `VideoCard`（桌面 hover / 移动 finger preview），两边不一致
	2) 修复：`_Tile` 换成 `VideoCard(compact: true, showDuration: true, margin: zero, hoverPreview: !isAuto, preview: _fp.isActive)`；`PlayerEndCard` 新增 `fingerPreview`，卡片外的 `Listener` 接 `_fp.onPointerDown`；screen 传 `_fp`
	3) `VideoCard` 新增 `hoverPreview` / `showDuration` / `margin` 三个参数（默认值保持现有调用不变）；`_dur` 在 compact 时贴底 4dp，不再浮在中间
	4) 倒计时那一格**禁用** hover preview：它本来就要自动播，环下再放一个动态画面是噪声
	5) 测试 12 例（新增「非倒计时格可 hover、倒计时格不行」）；渲染复看宽屏，圆角 / 角标 / 栅格无回归；门禁全绿
	6) 未验证：真实鼠标 hover 到 200ms 的预览起播（测试不模拟计时器与 `PreviewPlayer`）；移动端手指 sticky preview 的真机表现

26. 2026.11.13.1.40.PM.Friday
	*本批为 56f4100 引入的回归修复：完播卡片的推荐瓦片全空白*

	1) 用户贴图反馈「card 上面什么都不显示」：完播卡片的 Related 网格只剩文件名，三张瓦片一个海报、占位符、时长角标都没有；同时右侧 Related 侧栏的同名视频海报正常
	2) 定位：`FingerPreviewState.keyFor(path)` 用 `putIfAbsent` 按 path 缓存 GlobalKey，**同一个 path 永远返回同一个 GlobalKey 实例**。56f4100 把瓦片从裸 `VideoPoster`（无 key）换成 `VideoCard(key: fingerPreview?.keyFor(item.path))` 后，完播卡片与 Related 侧栏/剧集 sheet 对同一批 path 申请到同一个 GlobalKey
	3) 机制取证（不是猜测）：GlobalKey 一个 widget 树只能挂一处，第二处出现时框架会把先挂载的 element 搬到后挂载的位置，**先挂载的那一面被静默截断**——所以侧栏有海报、卡片瓦片空白，且不报错（`_debugVerifyGlobalKeyReservation` 在 assert 里，release 不抛）。探针复现：完播卡片 + 380dp 侧栏同树 → `Multiple widgets used the same GlobalKey`；卡片 + 剧集 sheet 同栈 → `Duplicate GlobalKeys detected in widget tree`
	4) 修复：GlobalKey 的归属从「文件」改为「表面」。`FingerPreviewState` 新增 `surface(name)` 返回 `FingerPreviewSurface`，key 的缓存键变成 `surface\0path`，`isActive` 同源；7 个调用点全部迁移——Related 列表 `playerRelated`、剧集 sheet `episodeSheet`、完播卡片 `endCard`、视频网格/列表 `videoBrowser`、首页两行 `homeRecommended`/`homeRecent`（顺带替掉 `'recent:${path}'` 那个字符串前缀 hack）
	5) 同一批修掉三个真实问题
		① 倒计时标签恒为 `8s`：`widget.countdown.inSeconds` 是常量，环在走数字不动。改为 `_remainingSeconds()` 读同一个 `_count` 控制器（向上取整），实测 8s→5s→2s；`0` 时显示 `now`
		② Day 模式瓦片不再是固定深色：DESIGN.md 明写「fixed dark tokens, never the page's semantic colours」，但换 `VideoCard` 后 Card 底色读 `RCrmColors.char`（Day = 奶油 #E3DCCD），浮在固定深色卡片上；时长角标底色也是 `char`，对卡片底 1.00:1（角标消失）。`VideoCard` 新增 `mediaSurface`，卡片底色/占位符/角标/加载态全部走 `player*` 固定 token；完播卡片与剧集 sheet 都置 true
		③ Day 模式投放页低对比度硬编码色：`cast_remote_screen.dart` 文件夹图标 `0xFFFFB74D` 对 char 仅 1.27:1（改 `RCrmColors.warn`，Day 4.34:1）、连接状态点 `0xFF4CAF50` 2.04:1（改 `RCrmColors.ok`，Day 5.77:1）；`cast_scan_screen.dart` 提示卡底色 `0xFFFFF3CD` 对 Day 画布 **1.01:1（整张卡片消失）**，且该文件此前连 `config/theme.dart` 都没 import。新增 `RCrmColors.noticeSurface/.noticeInk/.noticeBorder` 三元组，Night 保持原奶油色（17.4:1），Day 反转成深琥珀底 + 白字（对画布 5.27:1、对卡片 4.34:1、正文 5.93:1）
	6) 顺带修正：Night 的提示卡墨色 `#8A6D1A` 对奶油底只有 4.43:1，压线不过 AA 正文 → 改 `#806415`（5.05:1）
	7) 测试：`player_end_card_test.dart` 新增 4 例（倒计时逐秒递减、Day 下瓦片仍是 `playerSurface`、完播卡片与 Related 侧栏同挂载不抛且两面都画出瓦片、同 path 两个 surface 得到两个 key）；`settings_appearance_test.dart` 新增 2 例（三状态色对 char ≥3:1 双外观、notice 三元组正文 ≥4.5:1 且对画布/卡片 ≥1.4:1 双外观）
	8) 渲染复看（`.local_backup/render_end_card_fix_test.dart`，真字体 1280×800）：完播卡片三张瓦片的占位符、时长角标（05:59 / 01:18 / 01:06）、文件名全部正常，侧栏同时正常
	9) 门禁：`flutter analyze lib test` 零告警、`flutter test` **774/774**、`cargo build --locked` 通过
	10) 未验证：真机（尤其移动端手指 sticky preview 在两 surface 间切换）、真实鼠标 hover 起播、Day 模式真机渲染

	11) 顺带两项（同批、同属审查清单）：① 启动闪屏——`main()` 在 runApp 前已解析 SharedPreferences，新增 `SettingsService.prime(prefs)` 与静态 `primedAppearance`，`SettingsNotifier.build()` 用它种下外观，首帧即用户自己的主题（探针：night+safelight 存量首帧即 `darkPitch`+safelight，不再是默认 Day 奶油色）；`load()` 读同一批键、落在同值，种子不产生可见变化；`clearPrimedAppearance()` 供测试复位；② `platform_bridge` 契约补洞——3 个测试文件硬编码的通道字符串改从 `PlatformBridge.screen/.storage/.window` 取（否则改 bridge 常量它们会静默失配）；4 个 service 的裸 `MethodChannel` 别名加 `@visibleForTesting` 并在文档里写明 app 侧走哪个 bridge 方法，让「绕过 bridge」在 analyze 阶段可见

	12) 用户反馈（修完空白瓦片后的真机复看）：点击完播卡片第一格（转圈的倒计时瓦片）不是立即播那个视频，而是**重放原片**。定位：`_autoOverlay` 的压暗层是裸 `ColoredBox(color: 0x73000000)`，而 `_RenderColoredBox` 的命中行为是 `HitTestBehavior.opaque`（Flutter 源码 basic.dart:8393）——整块瓦片的点击被压暗层吞掉，瓦片自己的 tap 永远进不了竞技场，点击沿祖先落到画面自己的手势处理器上；播完的文件上 `_togglePlayPause()` 按 mpv 的「播放列表已结束」语义**从 0 重放原片**。探针复现：点环中心 → `picked=null, wrapperTaps=1`（点普通瓦片则 `picked ✓, wrapperTaps=0`）
	13) 修复：压暗层与圆环是装饰，包进 `IgnorePointer`（只有 `Cancel` 角标保留自己的处理器）；探针复测点环中心 → `picked=深探大健身房.mp4, wrapperTaps=0`。新增回归 1 例「tapping the ring tile plays THAT video」，断言点倒计时瓦片中心拾取的是 offer 本身
	14) 顺带核对 DESIGN.md「The whole tile is the yes」条目，补上这个 widget 树陷阱的说明（装饰性覆盖层 + 透明 ColoredBox = 点击吞噬）

27. 2026.11.13.3.50.PM.Friday
	*本批为 Rust 端性能 / IO / 冷启动专项：先修掉未使用依赖告警，再用实测探针定位并修掉 6 处真实瓶颈*

	1) 触发：用户贴出 `cargo build --release` 的唯一告警——`unused dependency 'windows-sys'`（`crates/rcrm-flutter-bridge/Cargo.toml:62`，声明了 `Win32_System_Threading` + `Win32_Foundation`），并要求顺带体检 Rust 端性能、IO 性能、冷启动性能
	2) 告警根因与处理：全仓库 `.rs` **零处** `windows_sys` 引用（grep 确认），该依赖自第一个提交（7010bc6）起就没被用过 → 直接删除 `[target.'cfg(windows)'.dependencies]` 整段。`windows-sys` 仍作为 `anstyle-wincon` 等的**传递依赖**留在 Cargo.lock 里，不需要动
	3) 先建测量工具再改代码：新增 `tests/perf_probe.rs`（3 个 `#[ignore]` 探针，不进门禁；`cargo test --release --test perf_probe -- --ignored --nocapture --test-threads=1`），分别测冷启动、字节流、WebDAV 三组；所有数字都是本机 release 实测，不靠估算
	4) **accept 循环 50 ms 轮询（最大的一处）**：`Server::serve` 把 listener 设成 non-blocking 后 `accept()` 轮询，WouldBlock 就 `sleep(50ms)`。新连接落在两次轮询之间就得等满 50 ms。归因实验：新开连接 50.30 ms vs 同一连接上 keep-alive 再发 0.29 ms → 差额 50.0 ms 正是轮询间隔，与请求处理无关。改为**阻塞 accept**（连接到达即刻返回），另起一个 watchdog 线程在 shutdown 标志翻转时向 listener 连一次把 accept 唤醒（并用独立的 `watchdog_stop` 让 watchdog 随 `serve` 退出而退休，避免线程泄漏；唤醒目标在 0.0.0.0/:: 时改指 127.0.0.1/::1）。**50.30 ms → 0.52 ms**
	5) **请求头逐字节读**：`read_until_double_crlf` 每次 `stream.read(&mut byte)` 只读 1 字节 → 每个 header 字节一次 `recv`（明文 TCP 下是一次 syscall）。改成 `HttpConn`（连接 + 8 KiB 读缓冲，`read_head` 找 `\r\n\r\n`、`read_body` 取 Content-Length），多读出来的字节留在缓冲里给下一次请求用（`Connection: close` 与 keep-alive 都不丢数据）。4 KiB header 的 keep-alive 延迟 **1.56 ms → 0.24 ms**
	6) **冷启动跑了两遍 KDF**：`bridge/server.rs` 的 `start()` 在 Step 2（验密码）与 Step 3（起服务）各调一次 `build_manager`，两次都把每个密码重新跑一遍 Argon2id → 白白多花一整轮 KDF。Step 2 建好的 Manager 在 Step 3 原样复用（此时 `ACCEPTED_KEYS` 已并入本轮密码，键集完全相同）
	7) **Argon2id 没开并行**：`rcrm-core` 的 `argon2` 依赖是 `default-features = false, features = ["alloc"]`，`parallel` 没开 → p=4 的 4 条 lane **单线程**串行算。打开 `parallel` 后 **84.0 ms → 31~36 ms**。rayon 已在 Cargo.lock 里（`heic` / `jxl-threadpool` 引入），**不新增任何包**
	8) **KDF 参数是磁盘格式的一部分，但必须留出「以后为了安全调参」的路**（本条中途改过一次设计，见第 16 项）
		① 事实：m=32768 KiB / t=7 / p=4 与 salt 推导都写进了文件头（`key_hash = BLAKE2b(derived_key ‖ file_size ‖ calibration ‖ salt)`），直接改会让全部存量文件解不开
		② 但**不能**把派生密钥的十六进制钉死当守卫：那只会告诉你「格式变了」，却保护不了真正要保的东西（老文件还能读），而且直接把「以后调高 KDF」这条路堵死
		③ 改成**多 profile**：新增 `rcrm_core::KdfProfile { m_cost, t_cost, p_cost, output_len }`，带 `V1`（现役）、`CURRENT`（新文件用）、`KNOWN`（读的时候逐个试）。`Manager` 内部每个密码存一个 `KeyRing { current, legacy }`——`current` 是当前 profile 派生的密钥，`legacy` 是旧 profile 派生的密钥。`read_file_header_any_key` 先试 `current` 再依次试 `legacy`，**命中文件头 `key_hash` 的那个就是它**
		④ **文件头格式一点没变**：profile 不落盘，靠「试已知 profile」还原。将来提 KDF 的正确姿势：老 profile 留在 `KNOWN` 里，`CURRENT` 指向新的，新文件用新的、老文件照读
		⑤ 代价：每个已知 profile 每个密码多一次 KDF（当前只有 1 个 profile → 仍是 1 次 KDF，冷启动成本不变，实测 37 ms 一致）
		⑥ `read_file_header_any_key` 的返回类型从 `(FileHeader, u32)` 改成 `(FileHeader, Arc<LockedKey<32>>)`——直接带回**匹配的**那个密钥，`ProjectedFile::open` 不再绕索引反查（索引反查在新模型下会拿到 current profile 的密钥，对老 profile 的文件是错的）
		⑦ `Manager` 新增两个公开字段 `current_profile` / `profiles`（默认 `KdfProfile::CURRENT` / `KNOWN`），供测试构造「升级后」的形态
		⑧ **profile 要短路**：读文件头时**profile 在外、key 在内** —— 先拿当前 profile 试遍所有 key，一个都不中才轮到旧 profile。反过来（key 在外）的话，第一个 key 的旧 profile 尝试会排在后面 key 的当前 profile 尝试前面，而当前 profile 才是绝大多数文件的情况
		⑨ `KeyRing` 改成按 profile 存（`by_profile: Vec<(KdfProfile, Arc<LockedKey>)>`）而不是把「当前」烤死进结构体：原来的 `current`/`legacy` 是在**注册时**定下的，之后再改 `current_profile` 就会拿错密钥去加密新文件；现在按 profile 查，改了也不会错位
	9) **目录扫描每条目 3 次 stat**：`resolve_ne_path_from_dir*` 对每个路径先 `is_file()` 再 `is_dir()`，`is_supported_file` 内部还有第三次 `is_dir()`。改用 `DirEntry::file_type()`（Linux 直接用 readdir 带回的 `d_type`，Windows 一次 `GetFileAttributesEx`），并拆出 `is_supported_file_name` 免掉多余的 `is_dir()` 探测。**2000 文件：114.4 ms → 1.5 ms**（热缓存取 3 次最小值，规避首轮冷缓存偏差）。Windows 上差距尤其大，因为 `Path::is_file()` 走 `fs::metadata` 要**打开文件句柄**再查属性
	10) **每请求的 metadata 探测**：`resolve_resource` 原本 `is_dir()` + `is_file()` + `fs::metadata()`（长度）+ `fs::metadata()`（mtime）共 4 次；`handle_propfind` 又 `is_dir()` + `exists()` 两次；FTP 的 `cmd_list` 同样两次。改为一次 `fs::metadata` 拿到长度与 mtime 并在各处复用（`Resolved` 改带 `meta` 字段）
	11) **`Manager::add_key` 的 `panic!` 是设计契约，本批保留**（中途一度被改掉，已按设计改回）
		① 契约内容：索引（crc32 of password）**就是密钥的身份**，`Manager` 用 `HashMap<u32, Arc<LockedKey<32>>>` 存密钥，同一索引注册两次 = 调用方弄丢了自己已经交过哪些密钥 → **必须炸**。而且「静默忽略第二次注册」对用户来说等价于「密码不管用」，是比崩溃更糟的失败模式
		② 真正的 bug 不在 core，在**调用方**：桥接层的多密码流程把 `ACCEPTED_KEYS`（已接受的）与用户刚输的密码拼在一起，用户「再输一次刚才那个密码」就会注册同一索引两次 → panic 打死启动线程 → `START_STATUS` 停在 1 → Dart 侧永远轮询「starting」，而 `stop()`（跑在 Flutter UI 线程上）会**无限等待**。修法是**修调用方，不是削弱 core**
		③ 把「索引即身份」这条规则提升成 core 的公开 API，调用方无法与 core 漂移：`rcrm_core::key_index(password) -> u32`（索引推导的唯一出处，`add_key` 也改用它）+ `Manager::has_key_index(idx) -> bool`。`has_key_index` 同时是 core 内部**唯一**回答「这个密钥注册过没有」的地方——`add_key` 的重复检查与 `use_key` 的存在性检查都走它，不再各自碰 `self.keys.contains_key`，membership 规则只有一处
		④ 桥接层 `build_manager` 按索引去重（`ACCEPTED_KEYS ∪ 新输的密码` —— 这里的重复是**框架拼出来的**，不是用户输入，去重是「调用方没弄丢自己交过哪些密钥」）；**CLI 不做预检查**：用户重复输入同一个口令就是让 core 的 `panic!` 直接炸（见第 30 条第 3 项）
		⑤ core 里只做了一处**不改变契约**的调整：panic 检查挪到 Argon2id 派生**之前**（原实现先派生再 panic，白白烧掉一整轮 KDF）。panic 的触发条件与消息 `Index ({}) of key exists!` 完全不变
		⑥ 两个 crc32 碰撞（不同密码撞同一索引，~2^-32）现在按索引去重会丢掉第二个 → 它的文件仍锁着 → GUI 会再要一个密码 → 用户换个密码即可，**可恢复**，不会卡死
		⑦ 启动线程仍整体套 `catch_unwind`：万一还有别的 panic 落到这里，落成 `-1`（error）而不是让状态永远停在「starting」；错误信息现在带上 panic 原文（唯一 realistically 能到这里的 panic 就是 `Index (...) of key exists!`）；`stop()` 的等待加了 10 s 上限，UI 线程不会被卡死
	12) 顺带：accepted socket 加 `TCP_NODELAY`（FTP 数据连接本来就有，控制连接与 WebDAV 没有）；响应头与响应体分两次 `write_all`，有 Nagle 时第二次写要等前一次的 ACK
	13) **未改的（查过，判定不动）**：`chacha20` 的 `StreamCipherSeek` 是 O(1)（只改 block counter + 丢一个 block），不存在「按 offset 重算密钥流」的问题；全加密文件的 1.79 GB/s 是 ChaCha20 单核吞吐的正常值（partial 模式 5.04 GB/s，因为只有头 2 KiB 走加密）；WebDAV 整文件 GET 的 280 MiB/s 是 **Windows loopback TCP 的天花板**（把传输块从 64 KiB 换到 256 KiB 无变化，投影读取本身有 4.8 GB/s，所以瓶颈在 socket 不在加解密），远高于 4K 码流所需；`ProjectedFile::open` 的 64 KiB `BufReader` 每次开文件分配一次，是瞬时的，不改
	14) 测试与门禁：`tests/kdf_compat.rs` 8 例 + 1 个 fixture 生成器（`#[ignore]`）：
		① **格式 fixture**（`tests/testdata/kdf_v1.bin`，164 字节，一个由旧版本用 V1 profile 加密的真实文件）——它必须永远能解开，且解出的明文（含一个多字节字符）、原始文件名、虚拟大小都要一致。这才是「存量库还能读」的真正守卫
		② **迁移能力**：老 profile 写的文件，在新 profile 成为 current 之后仍能读；新 profile 写的文件，在老 profile 仍是 current 时也能读（两个方向都测）
		③ **安全下限**：current profile 的 m_cost ≥ 32768 KiB、t_cost ≥ 7、p_cost ≥ 1、output_len == 32——**调高随便调，调低算事故**
		④ `KNOWN` 必须包含 `CURRENT`；派生必须确定（同密码两个 Manager 派生结果一致）；不同密码不得碰撞
		⑤ **重复注册同一密钥必须 panic**（`#[should_panic]`）+ 索引即身份（`has_key_index(key_index(pw))`）
		⑥ 负向验证过这个 fixture 真的能挡住破坏：故意把 salt 推导的 `^` 改成 `+` → fixture 用例立刻红，其余用例仍绿（它们只测自洽性）——说明它测的确实是「格式」而不是「当前实现的哈希」
		⑦ 其余：`tests/perf_probe.rs` 3 例（全部 `#[ignore]`，不进常规门禁）；`tests/perf_probe.rs` 3 例（全部 `#[ignore]`，不进常规门禁）；`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿；`cargo build --release --workspace` **零告警**（原 `windows-sys` 告警消失）；改动文件过 `rustfmt`（`src/main.rs` 顺带被 rustfmt 修正了 4 行既有排版）；WebDAV 集成 10 例全绿
	15) **KDF 守卫的设计改过一次**（用户指出「以后可能会为了增加安全性更改 KDF 参数」）：第一版把派生密钥的十六进制钉死当守卫 —— 那实际上把「调高 KDF」的路堵死了，而且它保护的不是真正要保的东西。改成现在这套：多 profile 机制 + 格式 fixture。派生值的 pin 已全部删除
	16) **KDF 耗时在这台机器上飘**：同一份代码背靠背测，Argon2id 单次派生在 37~70 ms 之间波动（第一次还要付 rayon 线程池的启动代价），机器负载高时明显变慢。比数字只能在同一次会话内背靠背比，别拿隔天的数直接对比
	17) 未验证：未在 Android/iOS 真机上跑过（Android 交叉编译通过即可，但真机性能未测）；rayon 全局线程池在移动端会按 `num_cpus` 起线程，低端机的内存占用未实测；FTP 的实测延迟未单独量化（本批只按同样的「一次 metadata 探测」原则改了 `cmd_list`）；未跑 `flutter analyze` / `flutter test`（本批没动任何 Dart 代码）；`KNOWN` 超过 2 个 profile 时的启动成本没量过

28. 2026.11.13.7.45.PM.Friday
	*本批为安全审查后的修复批次：先审出 1 个 Critical（自己复现），再按严重度逐条修*

	1) **Critical：Windows 上可读取挂载点之外的任意文件（路径穿越）** —— 本批最重要的修复
		① 复现（临时探针，实测后删除）：`GET /..\outside\secret.txt` 与 `GET /..%5Coutside%5Csecret.txt` **都读到了根目录外的文件**；纯 `..` 的防护是有效的
		② 根因：虚拟路径只按 `/` 切段，含 `\` 的整段被当成普通段 `disk.push(seg)`，**Windows 在 open 时才解析里面的 `..`**（实测 `C:\root\..\outside\secret.txt` 逃出 root）；`:` 驱动器前缀更狠——`PathBuf::push("C:")` 会**整体替换**路径，mount root 直接被丢弃。实测三种逃逸向量：`..\`、`..\.`、`C:`
		③ 修法：新增 `segment_is_safe()` + `append_segments()`，段里带 `\` 或 `:` 一律拒绝（`..` 仍走原有的「不弹到 root 之外」逻辑），单根 / 多根 / `_in_cwd` 三处解析统一走它
		④ 顺带：路径解析失败不再掐断连接。FTP 的 `CWD/LIST/MLSD/RETR/SIZE/MDTM` 改为回 550，WebDAV 改为回 404
		⑤ 回归测试：`ftp_path_traversal_with_windows_separators_contained`（4 个向量 + RETR + 正向对照）、`webdav_path_traversal_with_windows_separators_contained`（7 个向量 + 正向对照）。**负向验证过**：去掉守卫后两个测试都变红（WebDAV 报 "leaked a file outside the root"，FTP 报 "SIZE ..\secret.txt should be refused, got 213 18"）
	2) **High：FTP 明文口令进日志** —— `log_info!("CMD {} {}", verb, arg)` 把 `PASS <口令>` 原样打印，而默认日志级别就是 info。改为脱敏（`redact_arg()`，`PASS`/`ACCT` → `***`），并加单测钉住
	3) **High：WebDAV 请求体无上限且在鉴权之前** —— `Content-Length` 直接 `vec![0u8; cl]`，声明 4 GB 即可未授权打爆内存。改为上限 1 MiB，超出回 413 并断连（请求体本来就没被使用）
	4) **High：FTP 控制行无上限** —— 客户端不发 `\n` 即可单连接灌到 OOM（WebDAV 侧有 64 KiB 头上限，FTP 侧没有）。加 8 KiB 行长上限
	5) **Medium：`require_tls` 是死配置** —— 没有任何参数能置 true，WebDAV 代码也从不读它；即使打开，FTP 也只有 `cmd_retr` 检查，明文外泄的仍包括**解密后的原文件名**。现在：WebDAV 明文请求一律 403；FTP 的 `PASS` 回 534（且检查前置到匿名分支之前）、`LIST/MLSD/RETR/SIZE/MDTM` 回 530；CLI 新增 `--require-tls`
	6) **Medium：投影文件的 Content-Type 用错路径** —— 用的是磁盘名（`.<b72>`，无扩展名）→ 全部退化成 `application/octet-stream`，而 PROPFIND 用的是虚拟名 → 同一个文件两处报告的类型不一致，按 MIME 选解封装器的客户端会失败。改用虚拟名推导
	7) **Medium：accept 循环里线程创建失败会终止整个服务器** —— `spawn()?` 直接把错误抛出去，服务整体退出，且 `active` 计数泄漏。改为拒绝该连接、继续 accept
	8) **Medium：空口令能登录** —— `AuthConfig::with_credentials` 收到空口令时记成有效哈希，`Basic base64("user:")` 即通过。改为空口令 → `pass_hash: None`（fail-closed，所有校验一律失败），CLI 侧直接报错说明原因
	9) **Medium：一次偶发 I/O 错误让文件整个进程生命周期不可读** —— `OnceLock` 把 head 初始化的 `Err` 也缓存了。改为**只缓存成功**，失败可重试
	10) **Low：FTP 的 `REST`/`ABOR` 未鉴权** —— 补 `authed` 检查
	11) **Low：解码后的 URL 里的控制字符可以伪造日志行** —— `%0A` 会还原成换行。日志输出前过滤控制字符
	12) **查过但判定不动**：`read_at_with` 每 64 KiB 一次冗余 `lseek` + 一次 `ChaCha20` 重建 —— 实测读路径 1.55 GB/s（全加密）/ 4.57 GB/s（partial），而 WebDAV 整文件 GET 只有 203 MiB/s（socket 是瓶颈），**读路径有 7~20 倍余量**，这项优化只占读路径约 5%、端到端完全看不见；为它重构热路径的风险大于收益，不做
	13) 门禁：`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿（10 个测试目标，新增 4 个安全回归测试 + 1 个脱敏单测）；`cargo build --release --workspace` 零告警；改动文件过 `rustfmt`
	14) 未验证：未在 Android/iOS 真机上跑过（交叉编译通过）；`--require-tls` 的 FTPS 升级路径（`AUTH TLS` 后再 `PASS`）未做端到端测试；口令哈希仍是无盐 BLAKE2s（GUI 侧口令是随机的，爆破成本已高；CLI 侧用户自选口令仍偏弱，未改）

29. 2026.11.13.8.35.PM.Friday
	*本批撤销第 27 条引入的 KDF 多 profile 兼容机制——用户明确「KDF 的更新可以是 breaking change，不用考虑兼容性」*

	1) **撤销理由**：第 27 条为了「以后调高 KDF 时老文件还能读」，引入了 `KdfProfile`（V1/CURRENT/KNOWN）+ `KeyRing`（按 profile 存密钥）+ `Manager.current_profile/profiles` + `ordered_profiles()` + 读路径的 profile 外层循环，约 300 行。既然 KDF 变更允许是 breaking，这套机制的唯一存在理由就没了
	2) 现在的形态回到最简：`derive_key` 里三个常量 `KDF_M_COST=32768` / `KDF_T_COST=7` / `KDF_P_COST=4`（`pub`，供测试断言），`Manager.keys` 回到 `HashMap<u32, Arc<LockedKey<32>>>`，`read_file_header_any_key` 回到返回匹配索引
	3) **保留的三样东西**（都不为兼容性服务）：
		① `key_index()` + `has_key_index()` —— 索引就是密钥的身份，重复注册必须 panic（core 的设计契约）
		② **KDF 安全下限**测试：`KDF_M_COST ≥ 32768` / `KDF_T_COST ≥ 7` —— 调高随便调，**调低算事故**（防止手滑把 KDF 削弱了）
		③ **格式金丝雀** `tests/testdata/kdf_v1.bin`：一个由旧版本加密的真实文件。它解不开 = 格式变了 = 现有库全部需要重加密。这是**探测**而非**兼容**：KDF 真要改时按文档流程重新生成 fixture 即可
	4) 测试文件改名 `tests/kdf_compat.rs` → `tests/kdf_guard.rs`（原名说的是「兼容」，现在说的是「守卫」），用例从 8 减到 6（删掉 profile 专属的三个：安全下限挪到常量断言、KNOWN 包含 CURRENT、旧 profile 文件可读）
	5) 门禁：`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿（10 个测试目标）；`cargo build --release --workspace` 零告警；`cargo fmt --all --check` 0 差异
	6) 顺带记一笔：**口令哈希**（HTTP Basic / FTP 登录用的那个，与文件加密密钥是两回事）现在仍是无盐 BLAKE2s-256 + 非常量时间比较——未改，见第 28 条第 14 项

30. 2026.11.13.9.55.PM.Friday
	*本批是「重复/冲突/性能」审查后的修复批次。审查清单里 9 条被我自己的实测否掉 7 条（见第 4 项），只留下 2 条真问题并修掉*

	1) **R1：Live Photo / 动画检测各手抄了一份 fetch，抄的时候把保护丢了** —— 项目自己在文件头写明了标准（`net.dart`：「One shared HttpClient for all Dart-side fetches … keep-alive lets connections be reused」；`bounded_fetch.dart`：body 必须有 deadline，否则「服务器收下请求然后沉默 → future 永远 pending」），但 `live_photo.dart`（3 处）与 `animated_detector.dart`（1 处）各抄了一份旧的写法：每次请求新建一个 `HttpClient`、`grep timeout` 零命中
		① `bounded_fetch.dart` 增加 `range` 参数（支持 `bytes=a-b`，并接受 206）与 `fetchBoundedContentLength()`（HEAD 取 content-length）
		② `live_photo.dart` / `animated_detector.dart` 删掉手抄的 `_rangeFetch` / `_fileSize` / `_headerFetch`，改用 `bounded_fetch` → 共享 client、共享连接池、共享鉴权头、body 级 deadline 全部自动继承
		③ 顺带去掉 `headers` 参数：所有调用点传的都是同一个全局 `sharedAuthHeader`，而 `bounded_fetch` 用的就是它 —— 纯重复。`isAnimatedUrl` / `isLivePhotoUrl` / `phaseLivePhoto` / `createLiveMedia` 的签名因此简化，7 处调用点同步更新
		④ 净效果：这三个文件 **-130 行 / +71 行**
	2) **R2：「当前使用的密钥」被当成注册密钥存进了 map** —— `use_key()` 把 `Arc::clone(&self.keys[idx])` 塞进 `keys[MAGIC_KEY_USING = 0]`，于是同一个密钥在 map 里出现两次（实测 `key_entries: 2`，一个口令就 2 个条目）
		① 后果：`list_key_idxs()` 对一个口令返回 2 个索引（0 是假的，API 在说谎）；`read_file_header_any_key` 每个文件头把同一密钥验证两遍；口令的 crc32 索引若为 0 会与 magic 索引撞位 → 真密钥被覆盖 → 那个口令的文件静默打不开
		② 改法：新增 `Manager.using_idx: Option<u32>` 记录「当前选用哪个」，`keys` 里只留真密钥。`use_key()` 变成「选中」而不是「复制一份」；`use_provided_key()`（无任何调用点，且语义是「注册一个不在索引里的密钥」）删除；`MAGIC_KEY_USING` 常量删除
		③ CLI 侧 `if idx == Manager::MAGIC_KEY_USING { continue; }` 一并删除 —— 它本来会**跳过 crc32 恰好为 0 的真实密钥**
		④ 回归测试 `the_registry_holds_only_real_keys`（一个口令 → 索引表只有 1 条；`using_idx` 指向真实索引；再注册一个口令 → 2 条；切换选中不增加条目）
	3) **补 R2 漏掉的一半：「正在使用的 key 被删掉」怎么办**（用户提出）
		① 之前 `drop_key()` 只从 map 里删，不动 `using_idx` → 删掉正在用的那个之后，`using_idx` 指向一个不存在的索引，manager 声称自己有一个当前密钥、其实没有
		② 现在 `drop_key()` 在删掉被选中的那个时**同时清空选中**（`using_idx = None`），不变量「`using_idx` 要么为空、要么指向 `keys` 里真实存在的密钥」始终成立
		③ **「没有选中的密钥」是一个合法状态，不该用 panic 表达**：`get_using_key()` / `using_key()` 改成返回 `io::Result`，无选中时给出 `no key is currently selected`。原来 panic 的 `No current key` 既会在服务线程里炸掉连接，也把「本来就没选」和「选错了」混为一谈
		④ 顺带把 `drop_all_keys()` 的语义保住：CLI 在 crypt 结束后用它擦掉内存里的派生密钥 —— 若改成「选中时拒绝删」，这个擦除动作反而做不干净
		⑤ 回归测试 `dropping_the_selected_key_clears_the_selection`：删掉选中的 → `using_idx == None`、注册表里也没有了、`using_key()` 返回 Err 而非 panic；删掉**没被选中**的那个 → 选中不变、`using_key()` 仍然可用
		⑥ 写测试时才发现 `use_added_key()` 会**切换**选中（它本来就是「注册并使用」），所以「删掉另一个 key 不影响选中」这条必须先切回第一个 key 再删 —— 这条语义现在有测试钉住了
	3) **CLI 不预检查重复口令 —— 让 core 的 panic 直接炸**（用户明确要求）
		① 我先前在 CLI 的两处 `use_added_key` 之前加了 `has_key_index(key_index(pwd))` 预检查，把重复口令变成「这个密码已经试过了，换一个?」然后回到提示符 —— 这等于把 core「重复注册必须炸」的契约在调用侧悄悄废掉了
		② 已撤回：`run_crypt` 的重试循环与 `verify_encryption_passwords` 的补充密码，两处都恢复成直接 `use_added_key` → 重复口令由 `Manager::add_key` 的 `panic!("Index ({}) of key exists!")` 直接炸掉（这本来就是本项目既有的行为）
		③ 桥接层的去重**保留**：那里的重复是框架把 `ACCEPTED_KEYS` 和新输的密码拼在一起造成的，属于「调用方弄丢了自己交过哪些密钥」，去重才是修调用方而不是削弱 core
		④ 顺带把 `main.rs` 里一处与本批无关的 rustfmt 重排（一个 `&&` 链）也还原了，diff 里只留真改动
	4) 门禁：Rust `cargo build --locked` 通过、`cargo test -- --skip compare_` 全绿（10 个测试目标）、`cargo build --release --workspace` 零告警；Dart `flutter analyze lib` **No issues found**、`flutter test` **774 例全绿**；Android arm64（含 mobile-decode）交叉编译通过
	4) **审查中被实测否掉的 7 条**（我第一版清单里的，保留记录以免再犯）：① crc32==0 撞位 —— 2^-32，且重复验证的开销实测在噪声以下（同样 200 个头，重复跑 11.6~22.5 ms 飘），拿噪声当性能问题是错的 ② WebDavClient 绕过连接数上限 —— `_scanRecursive` 里 `await` 在循环中，扫描是**串行**的，并发 PROPFIND 恒为 1~2，碰不到服务端 32/50 的上限 ③ FileCache 锁中毒 —— 临界区里只有 HashMap 操作，没有能 panic 的代码；HashMap 的 OOM 是 abort 不是 unwind ④ FileCache 陈旧 —— `cryptFolderOp` 全项目**没有任何调用点**，GUI 不会在服务器运行时改盘 ⑤ `_headCache`/`_headPending` 无上限 —— 换库时 `clear()`，上限就是库大小 ⑥ `CertTrust.lastRejected` 全局单槽 —— 两张被拒证书都来自同一个服务器，钉错哪张都还是它 ⑦ 未命中全量扫父目录的 O(N²) —— 实测 300 文件目录，一次未命中 0.89 ms vs 命中 0.45 ms，多出的只是一次 `read_dir` + 300 次 map 查找（`virtual_name()` 只取已存的 `&str`，不重新解密），300 张照片总共多 132 ms，看不出来

31. 2026-11-13.11.45.PM.Friday
	*本批把 `--require-tls` 这个开关去掉，改用 FTP 协议原生的机制表达「必须加密」。协议细节按 RFC 4217 核对过*

	1) **先查协议（RFC 4217）**，几条结论：
		① `AUTH TLS` 只保护**控制连接**；**数据连接**的保护级别由 `PBSZ` + `PROT` 单独协商（§8：To protect the data channel as well, the PBSZ command, followed by the PROT command sequence, MUST be used）
		② 保护级别只有两个在用：`P`（Private，数据连接单独做 TLS 握手）与 `C`（Clear，数据连接不加密）；`S`/`E` 在 RFC 4217 里明确不用
		③ **数据连接的初始保护级别是 Clear**（§9：The initial state of the data connection MUST be 'Clear'）
		④ 服务器有权要求数据必须加密（§10.2 第 3 条策略：Insist on data protection）；级别不合适时 §9 给的响应码是 **521**（data connection cannot be opened with this PROT setting），§11.4 描述的 **522** 用于「当前保护级别不足以完成这次传输」
		⑤ `PROT` **必须**在 `PBSZ` 之后（§9：the PROT command MUST be preceded by a PBSZ command），且 FTPS 的 `PBSZ` 参数**必须是 0**（流式，无缓冲）
		⑥ 服务器可以「拒绝某些命令直到会话达到它能接受的安全级别」来实现自己的策略（§4.2）—— 这就是本次用来替代开关的机制
		⑦ RFC 4217 **没有定义隐式 FTPS**，也没有规定隐式 FTPS 必须拒绝 `PROT C`（那是服务器自己的策略）
	2) **去掉 `--require-tls`**（CLI flag + `ServerContext.require_tls` 字段 + WebDAV 的 403 检查 + 桥接层 + 4 个测试/示例里的引用）。理由：
		① 它和 `--ftps/--ftpes/--https` 表达同一件事（这台服务器能不能加密），两条路说同一件事
		② 单独用（不带任何 TLS flag）会产出**死服务器**：plain HTTP 无升级机制 → 一切 403；plain FTP 没有 tls_config → 客户端连 `AUTH TLS` 都做不到 → 永远 530/534
		③ 协议本身就有表达这个策略的原生机制（RFC 4217 §4.2），不需要第二个开关
	3) **改用协议原生机制**：
		① **显式 FTPS（`--ftpes`）**：口令只允许在 TLS 之后送 —— `PASS` 在 AUTH TLS 之前 → **534**。依据 RFC 4217 §4.2「拒绝某些命令直到会话被保护」。判据是「服务器配了 TLS 且不是隐式模式」，从协议推导，不再是独立开关
		② **`PROT C` 在隐式 FTPS 下 → 521**（原来用 534）。RFC 4217 §9 给的正是这个码：data connection cannot be opened with this PROT setting
		③ **`PROT` 必须在 `PBSZ` 之后**（显式模式，§9 的 MUST）；**`PBSZ` 参数必须是 0**（§9）
		④ WebDAV 侧不需要任何开关：`--https` 就是 TLS，`--http` 是用户明确选了明文
	4) **查代码时发现我之前说错了一条并已修正**：
		① 我上一轮说「隐式 FTPS 的数据通道默认是明文，除非客户端发 `PROT P`」—— **错**。代码里隐式模式的 `data_tls` 初值就是 `true`（`Stream::Tls(...), true, true, // Implicit FTPS → data connections default to encrypted`），客户端要降级必须显式发 `PROT C`，而那个本来就被拒。所以隐式 FTPS **本来就端到端加密** ✓
		② 因此「数据通道必须 PROT P（522）」这条检查是**不可达的死代码**，没有加；FEAT 里给隐式模式宣告 `PROT` 反而会引诱客户端去协商一个我们随后拒绝的降级，也没有加
	5) 新增/更新测试：`explicit_ftps_refuses_a_password_before_tls`（AUTH TLS 之前 PASS → 534）、`explicit_ftps_pbsz_must_be_zero`（PBSZ 1 → 504、PBSZ 0 → 200）、`implicit_ftps_rejects_prot_c`（534 → **521**）；删掉 `ftp_require_tls_refuses_plaintext` 与 `webdav_require_tls_refuses_plaintext`（开关没了）
	6) 门禁：`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿（10 个测试目标，ftps_integration 6 例）；`cargo build --release --workspace` 零告警；`cargo fmt --all --check` 0 差异（`main.rs` 里一处仓库既有的 rustfmt 重排被格式化）；Android arm64（含 mobile-decode）交叉编译通过
	7) **行为变化提醒**：显式 FTPS 现在拒绝在 AUTH TLS 之前送口令。FileZilla / curl / lftp 都是先发 `AUTH TLS` 再发 USER/PASS（RFC 4217 §12.1 的时序图就是这个顺序），不受影响；但「先 USER/PASS 再 AUTH TLS」的老客户端会收到 534

32. 2026-11-14.0.05.SAT.Saturday
	*本批按各家 RFC 把协议逐条核了一遍，核出两个真问题并修掉*

	1) **先更正我上一轮的引用错误**：我以为 **RFC 7151**（2023）是更新 FTPS 的那份 —— **错了**。RFC 7151 的主题是 **`HOST` 命令**（多虚拟主机），元数据只有 `Updates: 959`，**没有**改动 `AUTH`/`PBSZ`/`PROT`/数据连接保护级别。**RFC 4217 仍是 FTPS 的权威规范** ✓（我上轮引它是对的）。RFC 2228（FTP 安全扩展）给出 AUTH 的回复码体系：502 未实现 / 504 不认识机制 / 534 不愿接受 / 431 资源不可用 / 334 需要更多安全数据 / **234 已接受**
	2) **核出真问题 ①：匿名模式下 `USER` 一条就认证 —— 显式 FTPS 可以全程明文**（我上一轮删掉 `--require-tls` 后留下的漏洞）
		① `cmd_user` 在匿名模式（`auth.user.is_none()`）直接 `self.authed = true` 并回 230 —— **不需要口令**
		② 我上一轮只在 `cmd_pass` 上加了 TLS 闸 → 匿名模式下客户端根本不用发 PASS → `USER` → 230 → `PASV`+`RETR` → **解密后的文件名和媒体字节全程明文过网**
		③ 修法：TLS 闸同时覆盖 `cmd_user`。判据仍是「显式 FTPS」（`tls_config.is_some() && !implicit_tls`），从协议推导
	3) **核出真问题 ②：`AUTH TLS` 之后没有复位认证状态**
		① RFC 4217 §4.2：「the FTP protocol insists on a USER command be used … the USER command MUST still be issued by the client」；RFC 2228：接受 AUTH 会复位安全命令引起的状态变化，**服务器必须要求用户重新核准**
		② 原来的 `cmd_auth` 只换流、置 `use_tls`，`authed`/`username` 原样保留 → 升级前拿到的授权会跨过 TLS 升级继续有效
		③ 修法：`cmd_auth` 成功后 `authed = false; username = None;` → 客户端必须重新 USER/PASS
	4) **逐条核对过、确认本来就对的**（记录以免重复查）：
		- **RFC 2428 EPSV**：回复 `229 Entering Extended Passive Mode (|||port|)` ✓（地址字段留空）
		- **RFC 3659 MLSD**：事实名 `type=`/`size=`/`modify=` ✓，`modify` 为 14 位 `YYYYMMDDHHMMSS` ✓
		- **RFC 3659 REST**：`350 Restarting at <offset>` ✓，且 `rest_offset.take()` → **一次性语义** ✓（只用一次）
		- **RFC 3659 SIZE/MDTM**：`213 <size>` ✓ / `213 YYYYMMDDHHMMSS` ✓
		- **RFC 2640 UTF8**：FEAT 宣告 `UTF8` 且 `OPTS UTF8` → 200 ✓ 一致
		- **RFC 2228 CCC/ADAT**：未实现 → 502 ✓（拒绝 CCC 正是显式 FTPS 想要的）
		- **RFC 7151 HOST**：未实现 → 502 ✓（RFC 允许 500 或 502）
		- **RFC 9110 HTTP Basic**：401 + `WWW-Authenticate: Basic realm="rcrm"` ✓
		- **RFC 4918 WebDAV**：PROPFIND → 207 Multi-Status ✓，`<D:multistatus xmlns:D="DAV:">` ✓，`<D:status>` 用已声明的 `D` 前缀（无未声明命名空间）✓
	5) 新增/更新测试：`explicit_ftps_refuses_credentials_before_tls`（AUTH TLS 之前 USER 与 PASS 都 → 534；升级后 USER → 230）、`explicit_ftps_auth_resets_the_session`（升级后 `SIZE` → 530 未授权，必须重新 USER）；ftps_integration 共 7 例全绿
	6) 门禁：`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿（10 个测试目标）；`cargo build --release --workspace` 零告警；`cargo fmt --all --check` 0 差异；Android arm64（含 mobile-decode）交叉编译通过

33. 2026.11.14.0.31.SAT.Saturday
	*本批是 fetch 整合（第 30 批 R1）之后的健壮性收尾。用户指出整合后的 Dart fetch 仍「不健壮、不幂等」，要求「各方面的健壮性测试」。写测试时又核出一个真问题并修掉*

	1) **真问题：`isLivePhotoUrl` / `phaseLivePhoto` 在源文件 404/超时时会抛出，违背「兜底是 false / 返回 none」的契约** —— 第 30 批把 `_hasMovCompanion` 包了 try，但 Samsung 分支的 `_findMpvdBox` 与 `_phase` 里取源文件大小的那次 `fetchBoundedContentLength(url)` **没有包**，源文件一 404 就一路抛到调用方
		① 后果：`isLivePhotoUrl` 本该「永远返回 false 兜底」，实际会抛 `HttpException`；`createLiveMedia` 调 `phaseLivePhoto` 时源文件 404 → 崩溃而非返回 null
		② 修法：这两处 `fetchBoundedContentLength(url)` 改为 `.catchError((_) => 0)` → 0 触发既有的 `< 256`（`_findMpvdBox`）/ `< 1024`（`_phase`）提前返回 none，与「文件太小不是实况/动图」同一条路径汇合。Apple 分支的 `_hasMovCompanion` 本来就已兜底，未动
		③ `isAnimatedUrl` 本来就在 `_detectAnimated` 里整体 try/catch → false，不受影响，本批新测试把它钉住（见第 3 项）
	2) **「带 range 必须回 206」这个守卫的回归被显式钉住**（上一轮我加过、被用户否掉的那个）：本服对覆盖整文件的 Range 回的是 200（`RangeSpec::Full`），若再加 206 硬校验，会把小文件的实况/动图检测全打死。本批测试断言「整文件 Range 回 200 仍被接受」，防止该守卫悄悄回来
	3) **新增 3 个健壮性测试文件，共 17 例**：
		① `test/bounded_fetch_robustness_test.dart`（10）：206 整段返回、整文件 Range 回 200 仍接受、忽略 Range 且超 maxBytes 抛（不 OOM）、body 恰好等于 maxBytes 被接受、416→异常；`fetchBoundedContentLength` 返回 CL / 用 HEAD 而非 GET / 缺 CL 给 0 不崩 / 404→异常
		② `test/live_photo_robustness_test.dart`（6）：非空 companion→true（恰好 1 次 HEAD）、companion 404→false、0 字节 companion→false（回归 >0 检查）、`phaseLivePhoto` 缓存（第 2 次零网络）、`isLivePhotoUrl` 与 `phaseLivePhoto` 共享 companion 缓存、非实况结果也缓存（回归「所有结果都记忆」）
		③ `test/animated_detector_robustness_test.dart`（2）：整文件 200 小 body→isFalse（不挂起/OOM）、404→isFalse（不崩）
	4) **写测试时顺手修了一个测试桩 bug**（不影响生产）：`url('/x')` 拼出双斜杠 `http://host//x` → `Uri.path == '//x'` → 既破坏服务端路径匹配，又让 `live_photo` 把 companion 推导成 `//x.mov` 而命中不到。修正 `url()` 去掉前导斜杠；并让 `serveCompanion` 按路径路由（源文件恒 200 + 小 body），精确测「companion 缺失但文件在」而非把源文件 404 与 companion 404 混为一谈
	5) 门禁：`flutter analyze lib test` **No issues found**；新增 17 例全绿；既有 `bounded_fetch_test.dart` / `webdav_head_test.dart` 全绿，无回归（未跑全量 774 例：`TEMP` 已重定向到全新目录规避 `flutter_test_listener.*` 删除竞态，改动只在 fetch/检测层，已被针对性用例 + analyze 覆盖）

34. 2026.11.14.11.23.SAT.Saturday
	*本批按 RFC 9110 / 9112 逐条核对 WebDAV 的 HEAD 语义，把「HEAD 不得发送 content」下沉为唯一写出规则，并审查所有同类分支*

	1) **先查权威原文**（下载 RFC 纯文本核条文，不凭印象）：
		① RFC 9110 §9.3.2：「The HEAD method is identical to GET except that the server **MUST NOT** send content in the response」；且 SHOULD 发送与 GET 相同的头字段
		② RFC 9110 §8.6：HEAD 响应 MAY 带 Content-Length，但 **MUST NOT** 带一个不等于「等价 GET 本应发送的 content 字节数」的值 → 不能图省事把 HEAD 的 CL 写成 0，必须保留完整 body 长度，只抑制字节
		③ RFC 9112 §6.3 第 1 条：对 HEAD 的响应「is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body」→ 服务端写出的 body 对合规客户端不可见，会残留在 keep-alive socket 上，被读成下一个响应的状态行（落在响应拆分 / 请求走私的风险面）
	2) **触发背景**：上一批 live 图徽标排障实测到，HEAD 一个不存在的 `.mov` 得到 404 + 39B HTML；随后的 Range GET 在共享 keep-alive 连接上读到它 → `Invalid request method` → 徽标判定被吞成 false。当时在 Dart 侧用 `Connection: close` 隔离连接池，本批修上游
	3) **根因**：`write_response()` 无条件 `stream.write_all(body)`。`handle_get(head_only=true)` 虽在 4 个 RangeSpec 分支正确跳过了 `stream_body`，但 virtual root / `Resolved::NotFound` / `Resolved::Directory` 三处、以及 `not_found()`、401（鉴权在方法分派之前）、413、500 全部绕过 `head_only`
	4) **修法：单一 choke point + 编译器强制表态**
		① `write_response()` 增加必需参数 `head_only: bool`；`body` 仍是完整 GET 表示，`Content-Length` 照旧按 `body.len()` 生成（§8.6），只有字节写出被抑制（§9.3.2）。所有 17 个调用点逐一显式传值，漏一个就编译不过（本次编译确实抓出两处缩进不同的分支）
		② `dispatch()` 统一算 `head_only = req.method.eq_ignore_ascii_case("HEAD")`，覆盖 401 / 403 / 501；`handle_get` 三处、`handle_propfind` 全部传入
		③ `not_found()` 改为接 `&Request`，自己从 method 推导；两个调用点（handle_get 路径解析失败 / PROPFIND）不再需要各自记规则
		④ **413 在读请求体阶段失败、此时没有 `Request` 值** → `HttpConn` 新增 `last_method`，在解析出 method 后立即记录，413 用它判定；500 用已解析的 `req.method`
		⑤ `handle_propfind` 原先 4 处 `write_response_head + write_all + flush` 旁路统一收进 `write_response`，消除「绕过唯一写出点」这类同类缺陷的温床；`handle_get` 的 4 个 RangeSpec 分支保留直写（投影文件可达 GB 级，不能物化成 `Vec`），补注释钉住「头与 GET 完全一致、只跳过 `stream_body`」
		⑥ OPTIONS 恒无 body，显式传 `false` 并注明原因
	5) **同类分支逐条核对（记录以免重复查）**：416 分支 CL=0、两方法都无 content ✓；200/206 的 `Content-Length` / `Content-Range` 与 GET 一致 ✓；`read_request` 对带 Content-Length 的 HEAD 请求仍按长度读掉 body（符合 RFC 9112 帧规则）✓；401 / 403 / 501 / 413 / 500 已全部覆盖 ✓；FTP 无 HEAD 方法，无对应面
	6) **新增 3 例集成测试**（`tests/webdav_integration.rs`，11 → 14）：
		① `webdav_head_never_sends_content_but_keeps_get_metadata`：4 条 HEAD 可达路径（缺失文件 404 / 路径拒绝 404 / 目录 HTML / 普通文件），逐条断言 HEAD 无 content、状态码与 GET 一致、`Content-Length` 与 GET 一致
		② `webdav_head_404_does_not_poison_the_next_keep_alive_request`：同一条 TCP 连接先 HEAD 404 再 GET，断言头后第一个字节直接是下一响应的状态行且 GET 正常返回 —— 直接钉住上一批 Dart 侧踩的坑，回退服务端修复即红
		③ `webdav_head_errors_carry_no_content`：401（分派前）与 413（无 `Request` 值）都无 content、CL 与 GET 一致
		④ 测试辅助 `http_response_raw` **不按 Content-Length 读 body**（HEAD 合规响应声明了 GET 长度却无 content，按 CL 读会永久阻塞）；`start_webdav_server` 拆出 `start_webdav_server_with_auth` 供 401 用例复用，既有调用点行为不变
		⑤ **负向验证过守卫真的挡得住回归**：临时去掉 `write_response` 的 `!head_only` 条件（恢复修复前行为）→ 3 个新用例全红，keep-alive 用例直接报 `"<html><body>404 Not Found</body></html>HTTP/1.1 200 OK..."`，`webdav_head_returns_virtual_size` 仍绿（它走的是本来正确的流式分支）；恢复条件后 14 例全绿。说明测的确实是 HEAD 帧规则，不是测试桩自洽
	7) **Dart 侧 `Connection: close` 保留**：服务端已合规，但第三方 cloud WebDAV 仍可能对 HEAD 写 body，该防御继续隔离连接池；代价只是尺寸探测不复用连接。不回退，以免拆掉已有的回归守卫
	8) 门禁：`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿（WebDAV 集成 14 例）；`cargo fmt --all --check` 0 差异；`cargo build --release --workspace` 零告警；`flutter analyze lib test` No issues；`flutter test` 794 例全绿
	9) 未验证：未在真实第三方 WebDAV（Nextcloud / 群晖等）上验证其 HEAD 行为；HTTPS 下 `Connection: close` 带来的额外 TLS 握手成本未实测；未跑 Android/iOS 真机

35. 2026.11.14.11.48.SAT.Saturday
	*本批把响应策略收拢为请求级 `Responder`、按 RFC 9110/9112 写表驱动边界测试，并在审查中修掉 3 个真实缺陷*

	1) **抽象重构**：第 34 批把 `head_only` 做成 `write_response()` 的必需参数，17 个调用点各自传布尔、各自手写 `Connection` 头 —— 请求级语义被摊成样板。改为 `Responder<'a>` 值对象：一次从 `&Request` 派生 `head_only` + `close_after` 并持有 `stream`，所有响应经 `respond()` / `respond_stream()` 写出
		① `write_head()` 是 `Content-Length` 与 `Connection` 的唯一真相源：调用点传来的这两个头一律过滤；CL 恒按 GET 表示的长度生成（§8.6），**空 body 也发 0**（否则 keep-alive 客户端无法定界）
		② `respond()` 抑制 HEAD 字节；`respond_stream()` 用闭包产出 GB 级投影流且 HEAD 时完全不调用闭包 —— 原先 4 个 `write_response_head + stream_body + flush` 旁路全部收编，`None | Full` 两个等价分支合并
		③ `dispatch()` 里 GET/HEAD 合并为同一 handler；`not_found()` 不再接 `&Request`；`handle_options()` 从 5 个参数缩到 1 个；`head_only` / `conn_header` 从所有 handler 签名消失
		④ 413/500 无 `Request` 值时用 `Responder::for_error(stream, method)`，`HttpConn.last_method` 提供 HEAD 判定
	2) **按规范审出并修掉的 3 个真实缺陷**：
		① **请求帧定界（RFC 9112 §6.3(3)/(5)）**：原 `read_request` 用 `v.parse::<usize>().ok()` **静默忽略**非法 `Content-Length`，且完全不读 `Transfer-Encoding: chunked` 的请求体 → 未读字节残留在 keep-alive socket 上被解析成下一个请求（请求走私面）。现在 CL 非法 / TE+CL 共存 / TE 非 chunked → `InvalidData` → **400 + close**；TE: chunked → 新增 `read_line()` + `read_chunked_body()` 按 §7.1 解码并丢弃（含 chunk-ext 与 trailer，同受 1 MiB 上限）；"连接中途关闭"从 `InvalidData` 改回 `UnexpectedEof`，避免在已关闭的 socket 上写 400
		② **认证方案大小写（RFC 9110 §11.6.1）**：`h_strip()` 只认字面量 `Basic ` / `basic `，`BASIC` / `bAsIc` / 多空格全被拒。改为 `split_once(char::is_whitespace)` + `eq_ignore_ascii_case("Basic")`
		③ **空 body 响应的 Content-Length**：原 `write_response` 仅在 body 非空时补 CL，靠每个调用点自觉显式给 0；现由 `write_head()` 结构性保证
		④ **Connection token 列表（RFC 9110 §7.6.1）**：`Responder::new` 原用 `eq_ignore_ascii_case("close")` 判整个头值，`keep-alive, close` 会被当成 keep-alive 而多处理一个请求。改为按逗号切分逐 token 判定
		⑤ **零长度表示的 Range 下溢防护（RFC 9110 §14.2）**：核对 `parse_range_header` 的 `start >= content_length` 与后缀范围 `content_length == 0` 两处提前返回确实先于 `content_length - 1`，补 4 个空文件用例钉住
	3) **表驱动边界测试**（`tests/webdav_integration.rs` 14 → 24 例，内部约 75 个 case）：
		① `webdav_range_boundaries_follow_rfc9110`（17 case）：单点 / 开放 / 后缀 / 整文件 Range、end 越界 clamp、start≥size / start>end / `-0` → 416 且 `bytes */N`、非法语法与多段 Range → 忽略并 200 全文件；每例同时断言 `Content-Range`、body 切片与 `Content-Length == body.len()`（§14.2 / §14.4 / §15.3.7 / §8.6）
		② `webdav_head_matches_get_header_fields`（5 case）：200 / 206 / 416 与 Range 忽略路径下，**整个头集合**与 GET 逐项相同、HEAD 无 content（§9.3.2）
		③ `webdav_request_framing_errors_are_rejected`（8 case）：非法 CL（`abc` / `-1` / `1, 1` / `1.5` / 空）、TE+CL、TE 非 chunked / chunked 非最终编码 → 400 + `Connection: close`
		④ `webdav_chunked_and_head_bodies_are_consumed`（2 case）：chunked（含 ext 与 trailer）、HEAD 带 CL body，之后同连接再发 GET 仍须收到完整的第二个响应（§6.3 / §7.1 / §9.3.2）
		⑤ `webdav_basic_auth_scheme_is_case_insensitive`（7 case）：5 种大小写 / 空格拼写 → 200；Bearer / 错误口令 → 401 且带 `WWW-Authenticate`（§11.6.1）
		⑥ `webdav_every_response_declares_content_length`（10 case）：GET/HEAD × 文件 / 404 / 目录 / OPTIONS / PROPFIND / PUT / 未知方法，全部声明 CL，非 HEAD 时 CL == body 长度
		⑦ `webdav_request_body_limit_boundary`：恰好 1 MiB → 200，1 MiB+1 → 413 + close
		⑧ 新增 `http_pipeline`（一条连接连发多请求）与 `spec_fixture`（统一明文样本）；`http_response_raw` 继续**不按 CL 读 body**，否则合规 HEAD 会让辅助函数永久阻塞
		⑨ `webdav_connection_token_list_is_parsed`（3 case）：`keep-alive, close` / `CLOSE` / `close, keep-alive` 三种写法后同连接再发一个请求，必须只收到 1 个响应（不依赖超时，避免假阳性）
		⑩ `webdav_empty_file_ranges_do_not_underflow`（4 case）：0 字节文件上 `bytes=0-` / `-1` / `0-0` / `1-2` 全部 → 416 + `bytes */0`，验证 `content_length - 1` 不下溢
		⑪ `webdav_chunked_framing_errors_are_rejected`（3 case）：非法 chunk size、缺 CRLF、超大 chunk → 400 / 400 / 413 且关闭连接
	4) **负向验证（两轮，证明守卫非假阳性）**：
		① 同时临时回退 `h_strip` 与 chunked 消费 → 19 绿 / **2 红**，chunked 用例直接打印出残留字节被解析成 `HTTP/1.1 400 Bad Request`；恢复后全绿
		② 临时回退 `Connection` token 解析 → `webdav_connection_token_list_is_parsed` 红（实测 `left: 2, right: 1`，即多处理了一个请求）；恢复后全绿
	5) 门禁：`cargo fmt --all --check` 0 差异；`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿（WebDAV 集成 24 例）；`cargo build --release --workspace` 零告警；`flutter analyze lib test` No issues；`flutter test` 794 例全绿（Dart 未改，仍跑全量确认无回归）
	6) 未验证：未在真实第三方 WebDAV 客户端（curl / FileZilla / WebDAV 挂载）上做互操作验证；chunked 请求体仅按 §7.1 的最小形态（chunk-ext、trailer、1 MiB 上限）测试，未覆盖所有畸形 chunk 语法；未跑 Android/iOS 真机

36. 2026.11.14.12.08.SAT.Saturday
	*本批清理 Dart 端在服务端 HEAD 修复之前设置的补偿性补丁*

	1) **移除 `fetchBoundedContentLength` 的 `Connection: close`**：第 34 批加它是为绕开服务端「HEAD 404 也写 body」造成的连接池污染（脏字节被紧随的 Range GET 读成状态行）。服务端已在第 34 批按 RFC 9110 §9.3.2 改成 HEAD 不写 content（`Responder` 统一持有该规则），补丁只剩成本：每次尺寸探测都新建连接，HTTPS 下多一次 TLS 握手
	2) **回退 `isLivePhotoUrl` 的「只缓存 true」**：那是「假阴性可能被永久固化」前提下的取舍。服务端修好后不再需要，恢复「所有结果都记忆」——网格每次 rebuild 重查每个瓦片，未缓存的否结果会重复两次探测（companion HEAD + 64 KiB Range GET）。保留 `try/finally` 清理 `_isLivePending`：异常不得留下 poisoned future
	3) **回退对应测试**：`bounded_fetch_robustness_test.dart` 的 HEAD 用例恢复为只断言「用 HEAD 而非 GET」；删除 `live_photo_robustness_test.dart` 里字节级 raw socket 用例（它守卫的正是该补丁）。服务端 HEAD 帧行为仍由 `webdav_head_404_does_not_poison_the_next_keep_alive_request` 守卫
	4) **保留项（不属本类补丁）**：`truncateToMax`（对应「第三方服务器忽略 Range」，与服务端 HEAD 修复无关）、`clearLivePhotoCache()` 补齐清两个徽标缓存、`phaseLivePhoto` 缓存全部结果、`_findMpvdBox`/`_phase` 的 `.catchError` 兜底
	5) **端到端复验**：真实 `rcrm-server` 挂载该文件副本（临时 example，验证后已删），撤补丁后 `isLivePhotoUrl = true`、`phase = androidEmbedded`（offset 5896902），与修复前一致
	6) 门禁：`flutter analyze lib test` No issues；针对性 33 例全绿；全量 `flutter test` **793 例**全绿（794 − 1 个被删用例）；Rust 未改
	7) 已知取舍：第三方 cloud WebDAV 若仍对 HEAD 写 body，复用连接会被污染。该行为不在 rcrm 控制范围内，本轮按「服务端负责合规、客户端不做补偿」的架构处理，未在真实第三方服务器上验证

37. 2026.11.14.22.05.SAT.Saturday
	*本批按用户要求把项目里所有弹窗 / pop / popup / SnackBar / 底部弹层全部改用 flutter_smart_dialog 5.3.1 渲染。范围经用户确认：PopupMenuButton 全部用 showAttach 重建；SnackBar 改 showNotify；AlertDialog / SimpleDialog 保留 Material 外观，只把渲染层换成 SmartDialog.show*

	1) **初始化接线（lib/app.dart）**：
		① `MaterialApp.navigatorObservers` 加 `FlutterSmartDialog.observer`
		② 原 builder 包进 `FlutterSmartDialog.init(builder: …)`：桌面端仍返回 `TitleBarShell(child: FlutterSmartDialog)`，移动端直接返回 FlutterSmartDialog
		③ `initState` 设 `SmartDialog.config.attach = SmartConfigAttach(attachAlignmentType: SmartAttachAlignmentType.inside)` —— 该字段是 final，只能整体替换实例；inside 让 bottomLeft/topLeft 复刻 PopupMenuButton 的左缘对齐
	2) **模态弹窗改 SmartDialog.show**（保留 Material 视觉）：
		① settings_screen：缩略图缓存对话框、证书信任对话框、目录编辑器（`clickMaskDismiss: false` 对应原 `barrierDismissible: false`）
		② cloud_setup_screen：证书信任对话框；cast_receiver_screen：退出接收端确认；cast_remote_screen：退出投屏确认
		③ 所有 `Navigator.pop(ctx, value)` → `SmartDialog.dismiss(result: value)`；`thumb_cache_dialog` 3 处、`_DirEditor` 1 处同改
		④ 只改渲染层与关闭调用：`AlertDialog` / `SimpleDialogOption` / `ListTile` 原样保留；`_DirEditor` 内嵌的 `AlertDialog` 仍是内容而非独立路由
		⑤ 路由级 `Navigator.pop`（退出页面）一律不改：cast_receiver:349、cast_remote:652/660、image_viewer:249、search_screen:91/112、video_player:2379
	3) **底部弹层**：image_viewer 的 `showModalBottomSheet` → `SmartDialog.show(alignment: bottomCenter, maskColor: black 35%, clickMaskDismiss: true)`，内容包 `SizedBox(width: double.infinity)` 复刻整宽面板；`onActualSize` 的 `Navigator.of(sheetContext).pop()` → `SmartDialog.dismiss()`
	4) **SnackBar → showNotify**：cast_remote 3 处（Play/Stop failed = error，TV unreachable = warning）、cloud_setup `_showErr`（error）、settings `_snack`（success）、`DoubleBackGuard.hint`（warning，displayTime 1500ms，保留 `hint(BuildContext)` 签名以免动调用方）
	5) **新建 `lib/widgets/smart_popup_menu.dart`**：`SmartPopupMenu<T>` + `SmartPopupMenuItem<T>`
		① 触发器包 `InkWell`（可带 Tooltip），点击调 `SmartDialog.showAttach(targetContext: 触发器 context)`
		② 向下菜单 `Alignment.bottomLeft`、播放器向上 `Alignment.topLeft`（`openUpward: true`），配合全局 inside
		③ `maskColor: Colors.transparent` + `clickMaskDismiss: true`：菜单不压暗页面，但外部点击仍由遮罩捕获并关闭
		④ `onOpened` 在触发时同步调用；`onClosed` 映射 `showAttach` 的 `onDismiss`（覆盖选中与取消两条关闭路径）
		⑤ **`SmartPopupMenuItem` 做成 StatelessWidget 而非纯数据**：旧测试用 `find.byType(PopupMenuItem<T>)` 取行矩形/祖先关系，做成 widget 后 `find.byType(SmartPopupMenuItem<T>)` 可直接替代；每项自带 InkWell + 默认 16/10 padding，选中即 `SmartDialog.dismiss(result: value)`
		⑥ `backgroundColor` / `elevation` / `borderRadius` / `constraints` 可配，用于播放器的 playerSurface、8 高程、RCrmRadii.md 与模式菜单 240–300dp
	6) **替换全部 7 个 PopupMenuButton**：media_toolbar 3（组织方式 / 排序 / 扩展名过滤）、player_controls 2（倍速 / 播放模式，openUpward）、cast_remote 1（更多菜单）、cast_receiver_qr 1（切换 LAN 地址）。播放器的 onSelected 不再顺手置 `onMenuVisibilityChanged(false)`，改由 onClosed 统一处理，避免重复
	7) **清理因迁移而死的代码**：player_controls 删除 `_speedItemHeight`、`_menuPadding`、`_modeMenuHeight`、`_modeRowHeight`、`_measureHeight`、`_heightCache`、`_modeItemPadding` / `_modeGlyphColumn` / `_modeCheckColumn` / `_modeRowBreathing` / `_modeItemHeight` —— 这些是给 `PopupMenuItem.height` + 负 offset 算出来的，改用锚定布局后失去意义
	8) **测试更新（5 文件）**：
		① 三个菜单测试的 MaterialApp 加 `navigatorObservers: [FlutterSmartDialog.observer]` + `builder: FlutterSmartDialog.init()`，否则 showAttach 无处渲染
		② `find.byType(PopupMenuButton<X>)` → `SmartPopupMenu<X>`；`PopupMenuItem<X>` → `SmartPopupMenuItem<X>`；`widgetWithText(PopupMenuItem<String>, …)` 同改
		③ `thumb_cache_dialog_test` 的 harness 从 `showDialog` 改 `SmartDialog.show`（对话框内部已用 `SmartDialog.dismiss`）；`settings_cache_entry_test` 的 MaterialApp 加同样初始化
		④ 删掉「向上偏移等于菜单真实高度」用例（负 offset 机制已不存在），改为「菜单落在触发 chip 之上且各字号不溢出」
		⑤ video_folders_test 的两处菜单选择后补 2 次 `pump()`：SmartDialog 的 dismiss 是异步链（动画 → post-frame → future → provider），原本 2 次泵不够；排序测试早已用 `_settlePrefs` 做过同样的事
	9) 门禁：`flutter analyze lib test` **No issues found**；`flutter test` **813 例全绿**；`cargo build --locked` 通过；`cargo test -- --skip compare_` 全绿
	10) 未验证：未在 Android / iOS 真机与桌面真窗口上做视觉与手势回归（测试只覆盖 widget 层）；菜单在极窄窗口下的实际锚定位置、播放器菜单向上的观感未截图核对；`SmartDialog` 与桌面自定义标题栏（TitleBarShell）叠加时的遮罩层级未实测
	11) **修复（2026.11.15 真机/真窗口复验后）**
		① **缩略图缓存的 Auto trim 目标选择框点是没反应的**：该对话框现在渲染在 SmartDialog 自己的 overlay 里，而 SmartDialog 的 overlay 在 App Navigator **之上**，所以对话框内部没有 Navigator 祖先；`DropdownButton` 要 `Navigator.push` 一个 `_DropdownRoute`，点击直接抛 "Navigator operation requested with a context that does not include a Navigator"（widget test 复现）。改用同属该 overlay 的 `SmartPopupMenu<int>`：触发器仍是「当前目标 + 下拉箭头」、菜单项带当前项对勾，选中即关闭并 `setState`。顺带修掉一个潜在崩溃：持久化的目标值若不在 `kThumbCacheLimitChoices` 里，`DropdownButton` 会 assert 直接打不出对话框，现在按原值显示并允许重选。
		② **播放器倍速菜单（以及 cast remote 的 More、库工具栏的菜单）变成整窗宽的深色大板**：`showAttach` 的锚定容器把整屏宽度交给子节点，而 `Column(crossAxisAlignment: stretch)` 会把它填满 —— 实测播放器倍速菜单横跨 1600px 窗口，覆盖整条控制栏所在的区域，这就是用户看到的「控件配色不对」。`SmartPopupMenu` 恢复 `PopupMenuButton` 自身的几何：默认 `112–280dp` 约束 + `IntrinsicWidth(56dp 步进)` + 菜单上下 8dp 内边距；行改成原生菜单的行高（`minHeight 48dp`、水平 12dp、垂直 6dp），并把面板的文字基线改回 `labelLarge`，Material 用 `MaterialType.card` + `surfaceTintColor: transparent`（播放器仍传 `playerSurface`/8 高程，颜色与旧实现逐像素一致）。
		③ 新增回归用例：`test/smart_popup_menu_test.dart`（菜单宽度 112–280、行高 ≥48、长文本收窄换行、选中回调）与 `test/thumb_cache_dialog_test.dart` 的「trim 目标可选且 Auto trim 带的是新值」。
		④ 桌面真窗口复验：Auto trim 选择框可选；播放器倍速/播放模式菜单恢复紧凑宽度、Ash 面板、Silver 标签与橙色选中项（截图核对）；菜单默认圆角回到 M3 菜单的 4dp（播放器仍显式传 8dp）。
		⑤ 门禁：`flutter analyze lib test` **No issues found**；`flutter test` **818 例全绿**（原 813 + 5 个新回归用例）。

38. 2026.11.15.15.05.SUN.Sunday
	*修图片 viewer 的「双指缩放时下拉关闭与缩放抢手势」：pinch 期间任一根手指向下移动都可能触发 pull-to-dismiss，把正在放大的照片往下拽，松手还会直接关掉 viewer*

	1) **根因**：下拉关闭由页面外层的原始 `Listener` 自己维护一套状态（`_axis` / `_dragEngaged` / `_pulling` / `_pullGesture`），缩放与翻页则由 `ZoomableViewport` 的 scale recognizer 维护另一套；两者互不知情。第二根手指按下会重置 `_pointerStart`，之后任一根手指相对该原点的向下位移都能通过 8px 轴锁触发 pull；`_isZoomed` 只在缩放超过 1.01 后才拦截，所以 pinch 的起始阶段、纯双指平移、以及 pinch 后抬起一根手指继续下拖，全都能触发下拉。widget test 复现：双指下拖 240px 与 pinch 同时下移 120px 都会在旧实现上把 viewer 关掉
	2) **统一 gesture 模型**：新建 `lib/utils/viewer_gesture.dart`——不可变状态树 `ViewerGesture`（持有当前 pointer 集合与唯一 owner）+ 纯策略 `decideViewerGestureOwner`。优先级写成 `zoom（双指 / 已缩放）> page（横向）> pull（向下）`；第二根手指一按下就把整个 sequence 提升为 zoom，且此后不再降级；序列的 owner 只决定一次，弯指/改向都不能换道；最后一根手指抬起后 owner 保留，供随后到达的 scale end 读取（Listener 的 up 先于 scale end），`finish()` 才清空
	3) **接入页面**：`_ViewerPageState` 删掉 `_axis` / `_dragEngaged` / `_pulling` / `_pullGesture` 四个字段，改用一个 `_gesture`；`_pointerStart` 只属于序列第一根手指；pull 进行中第二根手指到达时 `_springBackPull()` 把照片弹回原位；新增 `onPointerCancel` 清理；pinch 打断横向翻页时 `_settlePager()`（旧实现的 re-anchor 路径已不存在）；`panEnabled` 由 owner 派生
	4) **测试**：`test/viewer_gesture_model_test.dart` 11 例纯状态树/轴锁用例；`test/viewer_gesture_test.dart` 新增 5 例真 viewer——双指里单指下拖、pinch 带下移、第二指打断 pull、pinch 后抬起一指再下拖、pinch 打断翻页。前 4 例在旧实现上均为红（逐例用备份旧文件跑过），第 5 例守的是新状态树取消旧 re-anchor 后的回弹路径
	5) 门禁：`flutter analyze lib test` **No issues found**；全量 `flutter test` **832 例全绿**（状态树 11 例 + 真 viewer 5 例）；Rust 未改
	6) 未验证：未在 Android / iOS 真机与桌面真窗口上做双指手势回归（widget test 覆盖的是手势状态与几何，不是真实触摸板/触屏事件）

39. 2026.11.15.18.40.SUN.Sunday
	*审查上一批暂存的海报改动后修复：桌面未知时长的首候选不再落在片头卡；移动端第一张截图有基线可判 stale；blank / resize / WebP 全部走 Rust，Dart 不再扫描像素*

	1) **桌面未知时长计划**：posterSeekPlan(Duration.zero) 改为 [30, 15, 3, 0.5, 60, 120, 240, 0]。上一版把 3s 放在第一位，而 3s 常常正是片头/Logo（非黑片，blank 会放行），于是整部电影被缓存成片头卡；旧列表在 0.0 被 blank 拒绝后还会试 30/15。240 也恢复了，长片头重新有候选。已知时长的比例计划不变
	2) **移动端第一张截图的 stale 基线**：上一版只用 previousRaw / previousJpeg 记录“本 job 看过的上一帧”，第一张没有基线；旧计划第一个位置是 0.0，拿到 seek 前的帧正好正确，新计划第一个位置是内容，同样的 stale 帧就会被当成新帧缓存。现在在第一次 seek 前先截一张 pre-seek 基线（raw 优先，raw 不可用才用 JPEG），第一个位置与基线相同就按 stale 重试；0.0 兜底位置例外，它接受与基线相同的帧——否则静态视频/幻灯片每个位置都是同一帧，会一张海报都出不来（isStalePosterFrame，4 条纯测试）
	3) **blank 走 Rust**：新增 rcrm_encode_poster_webp（mpv-poster，独立于 mobile-decode）。输入是 mpv screenshot-raw 的 tight BGRA；Rust 先对全部像素算 BT.601 均值，20..235 之外置 out_blank=1 并直接返回 null（不编码 WebP）；否则用共享的 bilinear_tap 新建 downscale_bgra_opaque_bilinear（BGRA→RGBA、alpha 255、目标宽 640）再走现有 webp::encode_rgba_webp。poster.rs 的 6 个测试、decode.rs 的 BGRA 缩放测试、lib.rs 的 2 个 FFI 契约测试覆盖 blank/alpha/尺寸
	4) **Dart 像素循环已删除**：poster_frame.dart 只保留 posterSeekPlan、sameEncodedFrame 与 isStalePosterFrame；NormalisedFrame / ScaledRgba / downscaleRgba / looksBlankLuma / normaliseBgraFrame 全部移除。ThumbWebpWorker 新增 op encodePosterBgra（BGRA 整帧一次 copy 进 native，worker 里调用 Rust，返回 bytes 或 blank）；rcrm_encode_poster_webp 的地址在 RustBridge 里按可选符号加载，桌面/旧 bridge 缺失时自动回落到 media_kit JPEG。ThumbnailService._posterMobile 现在：raw → worker/Rust；raw 不可用或 Rust 不可用 → media_kit JPEG（blank 仍由 rcrm_is_blank_frame 的 Rust 路径判定）
	5) **性能监测**：POSTER 日志继续保留并细分：plan、source/target、baseline、stale（含 compare_ms）、blank、hit（path=rust|jpeg、shot_ms、encode_ms、total_ms）、rejected、no_frame；桌面 desktop|hit 不变。下一轮真机只需 grep POSTER| 即可比较 Rust 路径与 JPEG 回落的实际耗时
	6) **独立 feature + 编译脚本**：poster 不再共用 mobile-decode，新增 Cargo feature mpv-poster；decode.rs 改为 any(mobile-decode, mpv-poster) 编译，解码 dispatch 与 fixture tests 仍 mobile-decode-only，poster 只需要共享的 DecodeBuf/bilinear_tap 和 WebP encoder。cargo test --features mpv-poster 可独立通过（33 例，无 AVIF/JXL/HEIC 依赖）。全部 7 个构建脚本更新：Android/iOS 默认同时开启 mobile-decode,mpv-poster（新增 -MPVPoster / --mpv-poster），Windows/Linux/macOS 默认都不开、新增同一个可选开关；PowerShell/bash 都把两个 feature 合成一个 --features 列表
	7) 门禁：flutter analyze lib test No issues；全量 flutter test 832 例全绿；cargo test -p rcrm-flutter-bridge --features mpv-poster 33 例全绿；cargo clippy -p rcrm-flutter-bridge --features mpv-poster --all-targets 零 warning；cargo clippy -p rcrm-flutter-bridge --features mobile-decode --all-targets 零 warning；cargo clippy --all 零 warning；cargo fmt --check 通过
	8) 未验证：未在 Android/iOS 真机测真实 mpv screenshot-raw 尺寸与旋转/变形视频（raw 尺寸仍以 player.state.width/height 为准，长度不符会回落 JPEG；90°/270° 同像素数的旋转是已知风险）；PosterRefresh 仍无菜单调用者，refresh 与 in-flight 的先后顺序未改

40. 2026.11.15.23.55.SUN.Sunday
	*按 docs/PLAN_MPV_POSTER.md 落地 libmpv 原生海报：删除 ffmpeg CLI 后端，海报生成从"桌面 ffmpeg / 移动 media_kit"改为按后端分级的 libmpv 与 mpv 两条路径*

	1) **删除 ffmpeg CLI 相关代码**：删掉 `lib/utils/ffmpeg_thumb_args.dart` 与 `test/ffmpeg_thumb_args_test.dart`；`ThumbnailService._posterDesktop`、`dart:io Process` 调用、`rcrm_gui_test` 的 ffmpeg pipeline 组一并移除；`url_consumers_test` 只保留 `safeUrl` 的规范化用例；`media_url.dart`/`webdav_client.dart` 里"给 ffmpeg 用"的注释改写。理由是本机实测 libmpv 1280×720 warm 帧 47–88 ms、本次 640×853 竖屏 seek 0 ms + frame 49 ms + encode 63 ms，均优于 ffmpeg 的 111–162 ms，且不再需要 PATH 上的外部程序
	2) **分级改成按后端命名，不再按平台**：新增 `utils/poster_backend.dart` —— `enum PosterBackend { libmpv, mpv }` + 纯函数 `choosePosterBackend({isIOS, hasLibMpv})`。`libmpv` = libmpv 自己渲染（iOS 以外的所有平台），`mpv` = media_kit `Player.screenshot` + Rust 编码（iOS，以及没有该导出的旧 bridge）。`hasLibMpv` 读 `RustBridge.libmpvPosterAddr`（符号缺失即 0），所以旧 bridge 自动走 media_kit，Dart 侧没有平台特判；该判断每次请求重算，不缓存（bridge 在启动后才 load）
	3) **Rust：新增 `libmpv-poster` 特性**（`libloading` 只在它下面启用；与 `mobile-decode`、`mpv-poster` 互不依赖）
		① `libmpv.rs`：运行时加载 libmpv（Windows `libmpv-2.dll` / Linux `libmpv.so.2` / macOS `libmpv.dylib` / Android `libmpv.so`），校验 `mpv_client_api_version ≥ 1.28`；`Api` 把符号拷成裸函数指针（`Symbol` 借用库会让所有类型带上生命周期），库用 `Box::leak` 保住；`Mpv`/`RenderContext<'mpv>` 两个 RAII 类型，后者借前者，编译期保证 render.h 要求的"先释放 context 再销毁 core、且同一线程"；`Surface` 提供 64 字节对齐、`stride = width*4` 的 BGR0 缓冲
		② `libmpv_poster.rs`：`mpv_create` → 选项（`vo=libmpv`/`hwdec=no`/`aid=no`/`sid=no`/`pause=yes`/`keep-open=yes`/`config=no`/`terminal=no`/`osd-level=0`/`tls-verify=no`/`http-header-fields`）→ `mpv_initialize` → **先建 render context 再 loadfile**（render.h 明说否则 mpv 会退回自己开窗的 VO）→ `loadfile` 等 `FILE_LOADED`；目标高度按 `dwidth/dheight` 的宽高比算（否则 SW_SIZE 会 letterbox，竖屏海报出现黑边），宽度是上限、不放大；每个候选位置：**先 drain 旧帧** → `seek absolute+exact` → 等 `MPV_EVENT_SEEK` → 轮询 `mpv_render_context_update` 的 FRAME 位 → render + `report_swap` → 用 `time-pos` 校验这一帧确实到了目标（否则继续等下一帧）→ 原地 alpha/blank → WebP。阶段超时 load 25s / seek 5s / frame 3s / 整 job 40s，所有失败只影响当前文件
		③ `poster.rs` 拆成共享层（blank band、`mean_luma_bgra`、新的 `make_opaque_and_mean_luma_bgra` 一次遍历同时写 alpha=255 并算 luma）与两个编码器：`encode_poster`（media_kit 截图：blank + 双线性缩放 + 编码）和 `encode_poster_frame`（libmpv：目标尺寸已是最终尺寸，只做原地 alpha/blank + 编码），模块改为 `any(mpv-poster, libmpv-poster)` 编译
		④ `webp.rs`：`encode_rgba`/`encode_bgra` 共用同一个 `encode`（`PixelLayout::Bgra8` 让编码器直接吃 libmpv 的布局，无通道交换），原 `encode_rgba_webp` 变薄壳
		⑤ `lib.rs`：`rcrm_generate_poster_async(url, headers, positions, target_width, quality, callback, ctx)`，三个字符串同步拷贝后起线程，`catch_unwind` 包住，回调带 `status`：0 = 有 WebP（`rcrm_free_webp_buf` 释放）、1 = 这个文件没出帧、2 = 本进程没有可用的 libmpv（Dart 据此回退 media_kit）；线程起不来时在调用线程回答
	4) **Dart 接入**：`services/poster_libmpv.dart` 用常驻 `NativeCallable.listener` + `Completer`（60s 兜底，晚到的回答自己释放 buffer）；`ffi/rust_bridge.dart` 新增 typedef、可选符号 `libmpvPosterAddr` 与 **`RustBridge.webpBufBytes`**（所有 `WebpBuf*` 的唯一零拷贝包装点，带 finalizer；`thumb_webp_worker.dart` 的重复实现与私有 `_WebpBuf` 结构体一并删除，`RustWebpBuf` 公开）
	5) **Dart 拆分与复用**：`services/poster_mpv.dart` 承接原 `_posterMobile` 全部逻辑（Player+VideoController 池、`_freeSlots` 空闲栈、`_waitForSeek` 双向 200ms 容差、stale 重试与 baseline、raw→Rust / JPEG→`rcrm_is_blank_frame` 两条路），并发槽与 30s 空闲池仍由 `ThumbnailService` 的定时器统一裁决；`_posterMobile`/`_posterDesktop` 消失，`ThumbnailService._runBackend` 只做"选后端 + 传 headers/durationHint"；`utils/poster_log.dart` 成为两条后端共用的 `POSTER|` 通道；`posterSeekPlan` 仍只有 Dart 一份（libmpv 后端据此生成 `positions` 字符串，Rust 再用自己读到的 `duration` 跳过越界位置）
	6) **暂停/恢复抽象化**：新增 `PosterParking`（`utils/poster_queue.dart`），`park/unpark/waitForResume` 三个动作，`ThumbnailService._ServiceParking` 实现；media_kit 后端现在是"park → stop → 等 resume → re-open → unpark"（parked 计数跨 re-open 保持，避免队列在 re-open 期间再起一个持锁的 job），顺带修掉旧代码在 re-open 抛异常时 `_posterParked` 可能变负的路径；libmpv 后端不需要 parking（不共享锁），但队列闸门仍然阻止播放时启动
	7) **并发下调**：`ItemCacheLimit.videoPosterConcurrency` 桌面 11 → 4（一个槽现在是一整个 mpv 上下文/Player，4K 下 11 路各自解码不现实；与评估报告 `8 的建议一致），移动端仍为 1
	8) **构建脚本**：Windows/Linux/macOS 默认加 `libmpv-poster`（新增/统一了用法注释，移除桌面上的 `-MPVPoster`/`--mpv-poster` 开关）；Android 默认 `mobile-decode,mpv-poster,libmpv-poster`（新增 `-LibMPVPoster` / `--libmpv-poster`）；iOS 明确不启用 `libmpv-poster` 并写明原因（libmpv 静态链接，无法 dlopen）
	9) **测试**：Rust 侧新增 `libmpv.rs` 的 API 版本/对齐/错误分类用例、`libmpv_poster.rs` 的 headers/positions/target_size/选项用例，以及 `RCRM_MPV_POSTER_TEST_VIDEO` 驱动的**真机端到端用例**（本机 720×960 竖屏视频实测通过：load 25ms、seek 0ms、frame 49ms、encode 63ms，输出 640×853 不透明 WebP）；Dart 侧新增 `test/poster_backend_test.dart`（三条规则），删掉 ffmpeg 相关测试
	10) 门禁：`flutter analyze lib test` **No issues found**；全量 `flutter test` **824 例全绿**（删掉 ffmpeg 相关用例、新增 3 例后端选择）；`cargo check` 三种特性组合（`mpv-poster` / `libmpv-poster` / 三个全开）零 warning；`cargo test -p rcrm-flutter-bridge --features libmpv-poster`、`--features mpv-poster` 全绿；`cargo clippy --all`、两种 poster 特性的 `--all-targets` 零 warning；`cargo fmt --check` 通过
	11) 未验证：未在 Android/iOS 真机、Linux/macOS 上实测（libmpv 加载路径与 SW 渲染只在 Windows 上跑过）；未测 4K/HEVC/长 GOP/多路并发下的内存与吞吐；`tls-verify=no` 与许可证结论仍是已知的待决项（见 `docs/PLAN_MPV_POSTER.md`）
41. 2026.11.16.3.20.AM.Monday
	*给视频/图片项目加长按与右键菜单，并给图库加双指手势：图片 tab 双指改列数、视频 tab 双指改列数/单双列，列表视图在宽窗口自动双列；全部复用已在 pubspec 中的库（material_ui / flutter_smart_dialog），不新增依赖*

	1) **项目菜单只有一个入口**：新增 `widgets/media_item_menu.dart` 的 `showMediaItemMenu`，视频 tab（网格/列表/打开的文件夹）、图片 tab（相册内与 Ungrouped 平铺）、搜索结果、首页推荐/最近两行都接同一份行定义（`mediaItemMenuEntries`）。长按（触摸，含 `HapticFeedback.mediumImpact`）与右键（桌面）都锚定在**指针位置**，不是卡片角落：`showSmartMenu`（`widgets/smart_popup_menu.dart` 新公开的 point-anchored opener）用 `targetContext: null` + `targetBuilder` 返回全局坐标——若同时把卡片 context 传进去，AttachWidget 会再按卡片高度偏移一次（实测），菜单会掉到卡片下方一整个卡高的位置
	2) **菜单方向在布局前就要定**：锚点接口给的是 alignment，不是"放不下就翻"的自动布局，所以新增 `utils/menu_placement.dart`：行高 48dp（随文字缩放，封顶 1.6×）+ 菜单 8dp 上下留白；下面放得下就向下，放不下且上面放得下就向上，两边都放不下取空间大的一侧。面板复用 `SmartPopupMenu` 的 112–280dp / 48dp 几何与 Ash 表面
	3) **行的取舍按"这个库能做什么"**：视频 = 播放 / 详情 / 在文件夹中显示 / 复制名称 / 复制路径；图片 = 打开 / 详情 / 复制名称 / 复制路径。库是只读的（服务端是加密目录的实时解密视图），重命名/删除/移动/分享都只能是灰行，一行都不放。详情面板图片复用查看器的 `ImageInfoSheet`，视频新增 `widgets/video_info_sheet.dart`（容器元数据有则追加行、没有就沉默——不写"无容器信息"，也不放骨架；技术行 + 文件夹/时长/修改时间始终来自 `MediaItem` 本身）。复制在桌面自绘 `SmartDialog.showNotify`，Android 13+ 交给系统提示，避免两次"已复制"
	4) **"在文件夹中显示"只给视频**：视频分组由 `videoFoldersProvider` 从已扫描列表派生，切到 'folder' 不重扫；图片 tab 的相册是在扫描时的 `MediaLibrary` 里构造的，揭示意味着整库重扫——一个菜单行不该偷偷触发全库扫描。从格式分组/未分组揭示时先把请求记在 `_revealPath`，切分组，等下一帧新文件夹列表出现后在 build 里解析目标并 post-frame 打开（不在 build 里 setState）
	5) **双指手势用原始 Listener，不用 ScaleGestureRecognizer**：新增 `widgets/two_finger_pinch.dart`。`ScaleGestureRecognizer` 会和网格自身的纵向拖动在竞技场里竞争，可滚动区域里通常拖动先赢，`onScaleStart` 根本不触发（Flutter issue 区多例）；`Listener` 不进竞技场，只读指针。它 `behavior: HitTestBehavior.translucent`（否则空状态/非可命中子组件上的指针永远进不来，本批测试第一轮就是这么红的），双指按下时把滚动物理换成 `NeverScrollableScrollPhysics`、结束后恢复，所以网格不会在"正在被改大小"的手指下面滚动。累积 scale 以手势起始跨度为基准（两指跨距之比），松开任意一根手指立即结束，第三根手指不参与
	6) **列数算术集中到 `utils/library_columns.dart`**：`pinchColumnCount`（向外张开 = 单元格变大 = 列数变少，四舍五入后 clamp；坏 scale 原样返回）、`pinchListColumns`（列表只有 1/2 列，20% 行程阈值 `kPinchListStep = 1.2` 才提交，双指滚动 scale≈1 不动）、`videoListColumnCount`（auto/one/two）、`videoGridBounds`（工具栏、build、手势共用同一 min/max clamp）、`imageGridMaxColumns`。图片 tab 双指实时改 `imageColumns`（2..按宽度上限），视频 tab 网格实时改 `videoGridColumns`，列表在 1/2 列之间切 `video_list_columns`
	7) **列表视图响应式双列**：新持久化设置 `video_list_columns`（'auto' | 'one' | 'two'，默认 auto）。auto 在 ≥840dp（Material expanded 断点）显示双列；双列列表是 `GridView` + `mainAxisExtent: 100`（`VideoListTile` 自己的固定行高），不用 childAspectRatio——否则行高随窗口拉伸，16:9 缩略图会被拉成条带。设置页 Display 区新增 Auto/One/Two 一行：手势只能设 one/two，必须留一个回到 auto 的门。**显式 Two 需要窗口 ≥600dp（Material medium）**：更窄时列表保持单列，双指手势也不会写入一个看不见结果的偏好——二次审查实测 375/414dp 下双列会让 VideoListTile 的固定 100dp 行溢出 54px（半屏手机的文本列不足 100dp，标题换两行再加两行元数据放不下），而 320dp 下工具栏本就有 43px 的既有横向溢出（与本次改动无关，单列同样复现）
	8) **附带重构**：`InfoRow` / `InfoRule` 抽到 `widgets/info_rows.dart`（图片/视频两个信息面板共用，避免两份私有行样式漂移）；`formatStamp`（"Sep 30, 2026 · 2:24 AM"）放进 `utils/format.dart`，`ImageInfoSheet` 改为调用它（输出用既有测试钉住，未变）
	9) **测试**：新增 `library_columns_test`（18 例：方向/起点/夹取/坏 scale/断点/显式 Two 的 599–600dp 边界）、`menu_placement_test`（6 例：行高与翻转/余量）、`two_finger_pinch_test`（6 例：单指不算、起始跨度为基准、松一指即结束、第三指不算、第三指抬起不结束、触控板 pan/zoom 的 scale=1 属于滚动）、`media_item_menu_test`（6 例：行的取舍/选中回调/向下与向上几何/剪贴板）、`video_info_sheet_test`（4 例：技术行、容器事实、无答案不声明缺失、scanner 分辨率回落）、`video_list_columns_test`（6 例：手机单列/宽窗双列/显式 One/显式 Two 在窄窗仍单列且不溢出/双指切双列/窄窗双指不写偏好）、`image_gestures_test`（2 例：双指改列数落到设置、长按出菜单）、`video_reveal_test`（1 例：菜单 → 切分组 → 打开文件夹）。另修正两个被设置页变长顶出可视区的既有用例（`screen_capture_test` / `settings_jump_history_slider_test` 改为先滚动到目标再断言/拖动）
	10) 门禁：`flutter analyze lib test` **No issues found**；全量 `flutter test` **873 例全绿**（原 824 + 49 个新用例）。Rust 未改动
	11) 未验证：未在 Android / iOS 真机与桌面真窗口上验真实双指、右键、触控板与长按震动；widget test 用的是 `TestGesture` 与 `sendEventToBinding` 模拟。另：`setSurfaceSize` 只改渲染面、不改 MediaQuery，菜单几何用例改用 `tester.view.physicalSize` 才让两者一致——真机上二者相同，这只是测试环境的坑
	12) **二次审查（2026.11.16）修复三处真实命中，并逐条排除假阳性**：
		① **600dp 双列行溢出 14px（1.0× 文本）**：`kTwoColumnListMinWidth = 600` 是双列被允许的下界，但 `VideoListTile` 的固定 100dp 行装不下「两行标题 + 时长 + 大小/扩展名」（实测内容 114dp），600–620dp 各列 3 行全部 RenderFlex overflow；`mainAxisExtent: 100` 只是把这个常量又抄了一遍。修：`utils/library_columns.dart` 新增 `videoListRowHeight(columns, textScale)`（单列 100 / 双列 116，按 `textScaler` 放大，封顶 1.5×），`VideoListTile` 增加 `height`（默认 100，搜索页等其它调用点不变），16:9 缩略图改成从 `height` 推导（`min(height*16/9, maxWidth*0.42)`），视频列表两处都用同一函数。
		② **单列在 1.2× 文本下也溢出 12px**（既有缺陷，本轮同一修复覆盖）：行高随 `textScaler` 放大后，`one/700/s1.2` 与 `one/700/s1.5` 均通过。
		③ **捏合翻 1↔2 列时列表跳回顶部**：旧实现是 `ListView` 与 `GridView` 两种控件二选一，换类型会重建 Scrollable、丢掉滚动位置（实测翻列前首行 `/p/10`、翻列后 `/p/0`）。修：列表在两种列数下都用同一个 `GridView`（`crossAxisCount: listColumns` + `mainAxisExtent: listRowHeight` + `mainAxisSpacing: 8`），Scrollable 不换类型，位置保留（实测翻列后首行 `/p/18`、`position.pixels > 0`）。新增用例：600dp 长标题不溢出、700dp 1.2× 不溢出、捏合翻列保留滚动位置。
		④ **排除的假阳性**：捏合首指按下会触发移动端「指下预览」——与今天任何一次单指触摸的行为一致，不是本轮引入；`SmartDialog` 的 attach 在向下溢出时会钉到屏幕底边（`attach_widget.dart::_adjustReactInfo`），所以 `menu_placement.dart` 里「两边都放不下取空间大的一侧」不会让菜单跑出屏幕；`InfoRule` 用的 `RCrmColors.hairline` 与旧 `ImageInfoSheet._hairline` 是同一个 getter，分隔线颜色逐像素不变。
		⑤ **未修（记录）**：`_copy` 在 Android < 13 上既无系统提示也无自绘提示（代码注释把「系统提示」当成 13+ 的既有能力），属于产品取舍，需要 SDK 判断才改。
		⑥ 门禁：`flutter analyze lib test` **No issues**；全量 `flutter test` **876 例全绿**（原 873 + 3 个新回归用例）。
42. 2026.11.16.4.30.AM.Monday
	*修上一批 libmpv 海报在 Android 上的整进程闪退：新海报 client 丢了旧 media_kit 海报播放器的内存/超时预算（mpv 默认 150+50 MiB demux 缓存、60 s 网络超时、按核数开帧线程），顺手把 stale 帧的整帧缩放去掉，并按「统一出清一轮」做了死代码审计*

	1) **根因（代码 + mpv 0.36 源码核实，非推测）**：
		① 旧路径 `MpvPoster` → `PlayerFactory.poster()`：demux 缓存 4 MiB + 4 MiB、`cache-on-disk=no`、`network-timeout=5`、`hwdec=auto-safe`（Android 走 MediaCodec）。
		② 新路径 `libmpv_poster::generate` 裸建 client，`options()` 未设任何缓存/超时项 → mpv 0.36 的默认值生效：`demuxer-max-bytes=150 MiB`、`demuxer-max-back-bytes=50 MiB`、`cache=auto`（HTTP 是 stream，缓存开启）、`network-timeout=60`、`hwdec=no`（软解）。单张封面从「8 MiB 缓存 + 硬解」变成「200 MiB 预读 + 4K 软解」，滑到第一个未缓存的大文件即被系统 OOM 杀掉整个进程（图片缩略图走 `ThumbWebpWorker`，不受影响，所以表现为「图片很快、某项视频必闪退」）。
		③ 放大项：`loadfile`/`mpv_terminate_destroy` 是阻塞调用，阶段 deadline 管不到；Dart 60 s 超时先释放并发槽（移动端并发 1），老 Rust 线程可能仍持 client + 缓存，新 job 再起一个 → 两份 200 MiB 并存。
		④ **逐项排除（二次确认）**：`Surface` 尺寸（`target_width` 来自 Dart 常量 640、height 被 `MAX_HEIGHT=8192` 夹住 → ≤21 MiB）、`render` 的 u32→c_int、空 `positions` 三条在现有调用链上不可达；`libmpv_sw.c` 的 SW 后端 `destroy` 是 nop、`priv` 在 init 里 `talloc_zero`，故 media-kit#480 那类「loadfile 失败后 `mpv_render_context_free` 崩」只属 GL 后端，本路径不适用；SW 参数形状（SIZE `int[2]*`、STRIDE `size_t*`、FORMAT/POINTER 的 data 本身就是值）与 `libmpv_sw.c` 的 `get_mpv_render_param` 逐项一致。
	2) **修复（`libmpv_poster::options`）**：`demuxer-max-bytes`/`demuxer-max-back-bytes=4M`（与旧 poster 播放器一致；一张封面不需要预读）、`cache-on-disk=no`（零明文落盘，写死而不是依赖默认值）、`network-timeout=5`（`loadfile`/`terminate_destroy` 不再能挂到 60 s）、`vd-lavc-threads=4`（软解 4K 的帧线程内存减半，长 GOP 的 seek 仍能在 `FRAME_TIMEOUT` 内解到目标帧）。
	3) **性能**：`drain()` 与 seek 前残留帧改用 `MPV_RENDER_PARAM_SKIP_RENDERING`（`libmpv.rs::RenderContext::skip`）——帧仍算已渲染、仍需 `report_swap`，但 SW 后端不再做色彩转换与整帧缩放；`drain` 的 `surface` 参数随之删除。
	4) **死代码审计（「统一出清一轮」的结论）**：27 个 `rcrm_*` 导出全部仍有 Dart 调用方（脚本比对 + 人工核）；5 种 feature 组合（default / `libmpv-poster` / `mpv-poster` / `mobile-decode` / 三开）`cargo check --all-targets` 零 warning、无「never used」。**JPEG 空帧函数 `rcrm_is_blank_frame` 不能删**：它只被 media_kit 后端的 JPEG 回退调用（iOS 正常路径，以及 libmpv 不可用时的移动端回退），且 `zune-jpeg` 还被 `qr_scan` 使用；`rcrm_encode_poster_webp` 同理（iOS 唯一编码器 + Android 回退）。出清结果：**0 个函数删除，1 个参数删除**（`drain` 的 surface）。
	5) **验证**：`cargo fmt --all --check` 干净；clippy 三种态（`libmpv-poster` / `mpv-poster` / `mobile-decode,mpv-poster,libmpv-poster`）零 warning；`cargo test -p rcrm-flutter-bridge --features libmpv-poster` 39 例、`--features mpv-poster` 34 例全绿；`RCRM_MPV_POSTER_TEST_VIDEO=testres/mayvid/驱蛇小鼠.mp4`（1280×720）跑通完整链路：load 30 ms → seek 200 ms → frame 14 ms → debug encode 984 ms，输出 640×360 不透明 WebP；同一用例对纯黑样本正确判 blank（no usable frame），说明空帧阈值未被本轮改动影响。
	6) **未验证**：未在 Android 真机复验闪退是否消失（本机无设备）；`demuxer-max-bytes=4M` 对超大文件的 seek 延迟未压测；R2 的「Dart 超时先行」只靠 `network-timeout=5` 缓解，未改成「并发槽跟到原生回调」；渲染线程上调用普通 libmpv API（`render.h` 明确禁止）仍未重构，其后果是丢帧/无封面而不是崩溃，列为后续硬化项。
43. 2026.11.16.9.40.AM.Monday
	*复核「空帧重试是否重开 mpv」：两个后端都是一次 job 一个实例；同时修掉首候选渲染 seek 之前那帧（REDRAW）的真实缺陷*

	1) **结论（空帧时能否复用同一个 mpv 实例）**：能，而且一直是。libmpv 后端 `libmpv_poster::generate` 每个 job 只 `Mpv::create` + `RenderContext::new` 一次，Dart 把整个 `posterSeekPlan` 一次性下发，Rust 在同一个 client 上逐位置 seek；空帧只是 `attempt` 返回 `Ok(None)`，循环继续。media_kit 后端一个 job `open` 一次，空帧 `break` 出重试循环后仍在池里同一个 `Player` 上 seek。所以 20–30 ms 是「每文件一次」的 client 创建成本，不是「每候选位置一次」。
	2) **最坏情况实测**（1080p 纯黑、6 个候选全判空，release）：libmpv 一次 job 537 ms（含 `load`）；旧 ffmpeg 路径同一文件同一组位置 1.3–5.6 s（每个位置还要试 input-seek 与 output-seek 两次、每次一个进程）。空帧判定发生在编码之前，空候选不付 WebP 编码，所以「全空」正是 libmpv 优势最大的场景。
	3) **复核中发现真实缺陷**：seek 之后 renderer 会先发一个 REDRAW/REPEAT 更新（`MPV_RENDER_FRAME_INFO_REDRAW`，flags=3），内容还是 seek 之前那一张，而 `time-pos` 已到目标，旧代码把它当成该位置的帧。2730×1440 样本 3.5 s：luma 0.00（ffmpeg 同位置 32.19），被判空帧；1080p 黑开头 30 s 同样 0.00（ffmpeg 69.75）；若文件开头不是黑帧，它会被静默当成该位置的海报（位置错位）。`drain()` 只能在 seek 前消费已经存在的帧，拦不住 seek 之后才来的 redraw。
	4) **修复**：① `wait_for_first_frame` —— `loadfile` 之后、第一次 seek 之前等首帧（2 s 上限），让 `attempt` 的 drain 先消费它，第一次 seek 不再和首帧抢跑；② `RenderContext::frame_info`（`MPV_RENDER_PARAM_NEXT_FRAME_INFO`）+ `is_previous_frame` —— `PRESENT` 且带 `REDRAW`/`REPEAT` 的帧画出但不认账，继续等真正的帧，只有到 deadline 仍没有新帧时才退回旧行为。
	5) **ABI 修正（跨平台）**：`mpv_render_context_get_info(ctx, mpv_render_param param)` 的结构体是**按值**传的；最初按指针数组绑定，Windows x64 的 16 字节结构体恰好也按隐藏指针传参所以本机「能用」，但 SysV（Linux/macOS）与 AArch64 会把它拆进两个寄存器。已改为按值绑定，与 `render.h`/docs.rs 的签名一致。
	6) **删除 `MPV_RENDER_PARAM_SKIP_RENDERING`**：本轮量化后发现，它只是把 SW 渲染器每个 client 的**一次性预热**（640×853 首帧 19.4 ms）从 drain 挪到目标帧——drain 画 19.4 ms 时目标帧 58 ms，drain 跳过 0.1 ms 时目标帧 77 ms，**总时间相同**。它并不省时间，反而依赖一个旧 libmpv 未必支持的参数（版本检查只要求 1.28）。已删除 `RenderContext::skip` 与 `PARAM_SKIP_RENDERING`，`drain` 回到 render.h 文档的 `render + report_swap`。
	7) **验证**：四种样本单位置首候选全部出图（720×960、1280×720、1920×1080 黑开头、2730×1440）；2730×1440 3.5 s 的海报与 ffmpeg 同位置 MAD 3.58、与 5 s 的 MAD 28.64（不是同一帧）；纯黑样本 6 个候选仍全部判空，阈值未变；删除 skip 后四种样本复测仍全部出图。门禁：`cargo fmt`、clippy（`libmpv-poster --all-targets -D warnings`）干净；`cargo test -p rcrm-flutter-bridge` 三种形态 40/34/25 例全绿，新增 `a_redraw_is_not_the_seeks_frame`；端到端用例改成单位置（正是出问题的首候选）。Dart 无改动：`flutter analyze` 干净、`flutter test` 876 例全绿。
	8) **未做/未验证**：跨 job 的 mpv client 复用仍是显式不做（render context 的线程亲和 + 常驻 4 MiB demux 缓存，换文件本来也要 `loadfile`）；空结果的会话内负缓存仍是产品取舍；未在 Android/Linux/macOS 真机复验 REDRAW 标志（`frame_info` 取不到时自动回落到旧行为）。

