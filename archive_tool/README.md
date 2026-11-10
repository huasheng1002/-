# 加密压缩包批量处理工具

> **合规声明（请先阅读）**
>
> 本工具仅用于处理**使用者拥有合法权限**的文件，例如自己打包、自己保管或已获授权整理的压缩包。
> 工具不具备任何密码破解能力，只按使用者提供的密码表顺序尝试；请勿用于破解他人文件密码、
> 绕过付费墙或任何侵犯他人权益的用途。使用本工具产生的一切后果由使用者自行承担。

按配置文件批量处理已加密的 zip / 7z 压缩包，完成一条固定流水线：

1. 扫描指定目录或文件；
2. 按密码表优先级尝试解压；
3. 删除文件名中包含广告关键词的文件（保留空目录）；
4. 把配置指定的文件覆盖式注入解压目录；
5. 用统一新密码重新压缩加密，输出到指定目录；
6. 输出重名时自动追加“副本”；
7. 原压缩包保持不动；
8. 全程写入日志（含明文密码，可关闭）。

---

## 1. 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10/11 x64 |
| Python | 3.9 及以上 |
| 主引擎 | `bin/7z.exe`（随包分发，7-Zip 25.01 控制台版，LGPL） |
| 依赖 | `PyYAML`、`pyzipper` |

安装依赖：

```bat
pip install -r requirements.txt
```

> `bin/7z.exe` 是 7-Zip 官方 extra 包中的 x64 独立控制台程序（原名 `7za.exe`），
> 支持 zip / 7z 的压缩、解压、AES-256、`-mhe` 文件头加密与 `-v` 分卷。
> 如需完整版（额外支持 rar、iso 等），可用 7-Zip 安装目录下的 `7z.exe` 替换，
> 并把 `7z.dll` 一并放入 `bin/`。分发时必须保留 `bin/License.txt`。

---

## 2. 目录结构

```text
archive_tool/
├─ main.py                  # 入口：参数解析与流水线编排
├─ config_loader.py         # 配置加载与校验
├─ scanner.py               # 输入扫描、分卷识别
├─ password_resolver.py     # 密码表与优先级
├─ archive_engine.py        # 7z 封装 + pyzipper 备选/兜底
├─ cleaner.py               # 广告文件删除
├─ injector.py              # 新增文件注入
├─ output_namer.py          # 重名“副本”命名
├─ logger.py                # JSON Lines 日志
├─ bin/
│  ├─ 7z.exe
│  ├─ License.txt
│  └─ README.txt
├─ config/
│  ├─ config.example.yaml
│  └─ passwords.example.yaml
├─ samples/
│  └─ process.log           # 日志样例（一次真实运行）
├─ tests/
│  ├─ test_core.py          # 纯逻辑单元测试
│  └─ test_pipeline.py      # 端到端测试（需要 7z.exe）
├─ requirements.txt
└─ README.md
```

---

## 3. 快速开始

1. 复制配置模板到项目根目录：

```bat
copy config\config.example.yaml config.yaml
copy config\passwords.example.yaml passwords.yaml
```

2. 修改 `config.yaml` 中的输入目录、输出目录、新密码、新增文件；
   修改 `passwords.yaml` 中的密码表。

3. 干跑，确认密码能命中（不写任何输出文件）：

```bat
python main.py --config config.yaml --dry-run
```

4. 正式处理：

```bat
python main.py --config config.yaml
```

5. 只处理一个文件：

```bat
python main.py --config config.yaml --only "D:\input\a.zip"
```

### 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | 全部成功 |
| 1 | 部分失败或跳过（密码未命中、损坏、不支持的分卷等） |
| 2 | 配置或环境错误（字段名会在控制台明确指出） |

---

## 4. 配置文件说明

```yaml
input:
  paths: ["D:/input/files", "D:/input/single.zip"]
  recursive: true
  extensions: ["zip", "7z", "zip.001", "7z.001"]

password:
  table_file: "D:/config/passwords.yaml"
  new_password: "统一的新密码"
  pass_via: "stdin"          # stdin | arg
  stdin_encoding: "auto"     # 可选：auto / utf-8 / cp936 ...

ad_keywords: ["广告", "vpn", "推广"]

add_files:
  - source: "D:/add/notice.txt"
    target_path: "notice.txt"

output:
  dir: "D:/output"
  keep_relative_structure: true
  rename_on_conflict: "副本"

archive:
  seven_zip_path: "./bin/7z.exe"
  allow_zip_fallback: false
  code_page: null            # null=自动；936=GBK；65001=UTF-8
  sevenz_encrypt_header: true
  zip_aes: true

log:
  dir: "D:/logs"
  file: "process.log"
  level: "INFO"
  log_password: true
  console: true
```

要点：

- **相对路径按当前工作目录解析**；只有 `archive.seven_zip_path` 在找不到时会再按配置文件所在目录找一次。
  建议在项目根目录运行，并使用 `./bin/7z.exe`。
- `input.extensions` 只写后缀（不含点）。分卷只需写入口后缀
  （`zip.001` / `7z.001`），同组其余卷不会单独入列。
- `ad_keywords` 子串匹配、不区分大小写、只匹配文件名，不匹配目录名。
- `add_files.target_path` 必须是相对路径，不允许 `..`、绝对路径或 Windows 非法字符。
- `keep_relative_structure: true` 时保留输入目录下的相对结构；`false` 时全部平铺到输出目录。
- `rename_on_conflict` 默认“副本”，仍冲突时追加序号：`副本2`、`副本3`……
- `log_password: false` 时日志中的密码字段输出 `******`。

### 密码表与优先级

```yaml
files:
  "D:/input/a.zip": ["pwd_a_1", "pwd_a_2"]
  "D:/input/sub/b.7z": ["pwd_b_1"]
default: ["常用密码1", "常用密码2"]
```

解析规则（严格按顺序）：

1. 路径规范化：绝对化、统一分隔符、按 Windows 规则大小写不敏感；
2. `files` 中精确匹配 → 按列表顺序尝试，日志记 `source=exact`、`index` 从 1 开始；
3. 未精确匹配 → 使用 `default` 顺序，日志记 `source=default`；
4. 全部失败 → `SKIPPED`，日志记录“密码未命中（已尝试 N 个候选）”；
5. 命中后记录命中密码、来源与优先级序号。

---

## 5. 流水线细节

对每个文件独立执行，单个文件失败不会影响其他文件：

1. 创建独立临时目录 `<系统临时目录>\archive_tool\<uuid>\`；
2. 按密码优先级解压；成功即记录命中密码；
3. 递归删除文件名含广告关键词的文件（空目录保留）；
4. 按 `add_files` 注入文件，父目录自动创建，同名直接覆盖；
5. 计算输出路径（重名加“副本”，压缩前即确定）；
6. 用新密码重新压缩：
   - 7z：`-t7z -mhe=on`（可配置）
   - zip：`-mem=AES256`（可配置）
7. 校验输出存在、可被 7z 列出、且**确实需要密码才能打开**；
8. 写日志（含明文密码，可关闭）；
9. `finally` 清理临时目录，清理失败只记 WARN。

> 若某条 `add_files` 注入失败，其余步骤继续执行；输出仍会生成，但该文件记录为 `FAILED`，
> `error` 中列出失败条目，避免出现“少了文件却显示成功”。

### 分卷处理

- `.zip.001` / `.7z.001` 视为入口，只把首卷交给 7z，7z 自动读取后续卷；
- 输出按首卷大小加 `-v<size>`，生成 `.001`、`.002`……；
- 无法读取源分卷大小时记录 WARN，按单卷输出；
- 传统 `.z01/.z02` 分卷 zip **不合并**，`SKIPPED` 并提示人工预合并。

### 输出命名

```text
a.zip            → a.zip
a.zip 已存在     → a副本.zip
a副本.zip 也存在 → a副本2.zip
v.7z.001 已存在  → v副本.7z.001（冲突检查覆盖同组所有卷）
```

命名完全由 Python 侧决定，不依赖 7z 的覆盖行为；原压缩包不删除、不改名。

---

## 6. 日志

- 文件日志为 **JSON Lines**，每行一个 JSON 对象，UTF-8 编码；
- 处理记录 `type=record`，过程消息 `type=message`；
- 控制台输出人类可读文本，`console: false` 可关闭。

每条记录至少包含：

```text
timestamp / source / output / status / old_password / password_source /
password_index / new_password / removed_files / added_files /
renamed / duration_ms / error / candidates / kind / volume
```

`status` 取值：`SUCCESS`、`FAILED`、`SKIPPED`；干跑命中的记录为 `DRY_RUN`。

一次真实运行的样例见 [`samples/process.log`](samples/process.log)。

> **安全提醒**：按需求 `log_password` 默认 `true`，日志中会出现**明文密码**。
> 生产环境请把日志目录放在受控位置并限制权限，例如：
>
> ```bat
> icacls D:\logs /inheritance:r /grant:r "%USERNAME%":(OI)(CI)F
> ```
>
> 或者把 `log_password` 设为 `false`。日志目录不要放在共享目录或同步盘中。

---

## 7. 已知限制

1. **传统 `.z01/.z02` 分卷 zip 不会被自动合并**：检测到即跳过并记录日志，需人工预合并。
2. **zip 的 `-mhe` 不生效**：zip 格式本身不支持加密文件名，文件名始终可见；`sevenz_encrypt_header`
   只对 7z 输出有效。
3. **日志默认记录明文密码**，存在安全风险；请限制日志目录权限或关闭该开关。
4. **分卷输出大小依赖源首卷大小**；无法读取时按单卷输出并记录 WARN。
5. 工具不具备密码破解能力，只按密码表顺序尝试。
6. **Windows 版 7-Zip 不能从管道 stdin 读取密码。**
   配置默认 `pass_via: stdin`，程序会先按任务书要求尝试 stdin；一旦确认 stdin 不可用，
   会自动回退到 `-p<password>` 并**记住该状态**，后续不再重复尝试。
   这意味着在 Windows 上密码会短暂出现在本机进程命令行中（同一用户的其他进程可能读取到）。
   如不需要该探测，可显式设置 `pass_via: arg`。程序会在日志中给出一次 WARNING 提醒。
7. **7-Zip 无法用非 ASCII 密码创建 zip**（实测 16.04 / 19.00 / 23.01 / 25.01 均报“参数错误”）。
   当 `new_password` 含中文等非 ASCII 字符、且输出为 zip 时，工具自动改用 pyzipper 写
   AES-256 zip，密码按本机 ANSI/OEM 代码页（简体中文为 cp936）编码，7-Zip / WinRAR 可正常打开。
   该场景需要安装 `pyzipper`；未安装时该文件记录 `FAILED` 并给出明确提示。
   zip 分卷 + 非 ASCII 密码的组合不受支持，会记录 `FAILED`。
8. 7z 格式的密码由 7-Zip 直接处理，支持中文；zip 的读取兼容 WinRAR/Bandizip 等按本机代码页
   加密的压缩包，但**不兼容按 UTF-8 编码密码生成的特殊 zip**（7-Zip 本身也读不了）。
9. 串行处理，不并发。大文件全程走文件系统与子进程，不会一次性读入内存。

---

## 8. 备选引擎（pyzipper）

- **触发条件一**：`archive.allow_zip_fallback: true` 且 7z 不可用，同时所有待处理文件都是
  **非分卷 zip**；
- **触发条件二**：zip 输出使用非 ASCII 新密码（见上文第 7 条），仅对该文件的压缩步骤生效。

备选引擎不支持 7z、分卷、`-mhe`，且 zip 仍使用 AES-256。
`py7zr` 未安装，代码中也没有进入生产路径的调用。

---

## 9. 测试

```bat
pip install pytest pyzipper
python -m pytest tests -q
```

- `tests/test_core.py`：配置校验、扫描、密码优先级、广告删除、注入、命名、乱码检测；
- `tests/test_pipeline.py`：需要 `bin/7z.exe`（可用环境变量 `APS_TEST_7Z` 指定其他路径），覆盖
  zip 全流程、7z `-mhe`、密码命中与 default 回退、重名“副本”、干跑、密码未命中、
  `.z01` 跳过、`.7z.001` 分卷、GBK 文件名、`-mcp=936`、非 ASCII 新密码、
  pyzipper 备选引擎、失败隔离与临时目录清理、日志脱敏。

未安装 7z 时端到端测试自动跳过。

---

## 10. 故障排查

| 现象 | 处理 |
| --- | --- |
| 退出码 2，提示 `archive.seven_zip_path` | 确认 `bin/7z.exe` 存在；相对路径按当前工作目录解析 |
| 提示“密码未命中” | 检查密码表路径写法；Windows 下大小写与分隔符不敏感，但盘符必须一致 |
| 输出校验失败“未检测到加密” | 检查是否被其他工具改写了输出；确认 `sevenz_encrypt_header` / `zip_aes` |
| 中文文件名乱码 | 在 `archive.code_page` 指定 `936`；null 时会在检测到乱码后自动用 936 重试 |
| 日志中文在 Git Bash 中显示乱码 | 日志文件本身是 UTF-8；用支持 UTF-8 的编辑器或 PowerShell 查看 |
| 临时目录占用大 | 处理结束会自动清理；异常退出后可手动删除 `%TEMP%\archive_tool` |

---

## 11. 许可

- 本工具源码可自由修改与分发；
- `bin/7z.exe` 来自 7-Zip 官方发行包，遵循 GNU LGPL（含 unRAR 限制），
  分发时必须保留 `bin/License.txt` 与版权声明；
- 详见 <https://www.7-zip.org/license.txt>。
