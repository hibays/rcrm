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
