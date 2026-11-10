bin/ 目录说明
=============

7z.exe
------
本目录内的 7z.exe 是 7-Zip 官方发布的独立控制台版本（官方包内的 7za.exe，
x64 架构），版本 25.01（2025-08-03），按任务书要求命名为 7z.exe 以便直接调用。
它支持 zip / 7z 的压缩、解压、AES-256 加密、-mhe 文件头加密与 -v 分卷，
足够本工具使用。

如需使用完整版 7z.exe（额外支持 rar、iso 等格式），可用 7-Zip 安装目录下的
7z.exe 替换本文件，并把同目录的 7z.dll 一并放入；也可在配置中把
archive.seven_zip_path 指向系统中的 7-Zip 安装路径。

License.txt
-----------
7-Zip 主许可为 GNU LGPL；其中 unRAR 代码受额外限制。分发时必须保留本文件。
详见 https://www.7-zip.org/license.txt

来源
----
https://www.7-zip.org/a/7z2501-extra.7z （官方 extra 包）
