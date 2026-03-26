# Apifox 供应链事件本地检测脚本

用于检测本机是否存在 2026 年 3 月 Apifox 桌面端供应链攻击的本地残留痕迹。

脚本文件：[`detect_apifox_compromise.py`](./detect_apifox_compromise.py)

## 背景

根据公开技术分析，Apifox 桌面客户端在 `2026-03-04` 到 `2026-03-22` 期间曾遭遇供应链攻击。被投毒的前端脚本会在本地收集和外传敏感信息，包括但不限于：

- SSH 私钥
- Git 凭证
- Shell 历史
- Kubernetes 配置
- npm token
- Apifox 用户信息

本仓库提供的是一个“本地 IOC 检测脚本”，用于扫描 Apifox 常见本地数据目录，查找公开披露的 IOC 和残留痕迹。

## 特性

- 纯 Python 标准库实现，无第三方依赖
- 支持 Windows、macOS、Linux
- 默认自动发现 Apifox 常见本地目录
- 支持额外指定扫描目录
- 支持文本输出和 JSON 输出
- 支持退出码，便于接入自动化脚本
- 不联网，不上传任何本地数据

## 检测内容

脚本会重点扫描以下几类残留：

- C2 / 外泄域名或路径
  - `apifox.it.com`
  - `/public/apifox-event.js`
  - `/event/0/log`
  - `/event/2/log`
- 本地存储 / 请求头痕迹
  - `_rl_headers`
  - `_rl_mc`
  - `af_uuid`
  - `af_os`
  - `af_user`
  - `af_name`
- 载荷特征
  - `foxapi`
  - `scryptSync`
  - `collectPreInformations`
  - `collectAddInformations`

默认会优先检查这些常见 Electron 数据位置：

- `Network`
- `Local Storage`
- `IndexedDB`
- `Cache`
- `Code Cache`
- `logs`
- `Network Persistent State`
- `Preferences`
- `Local State`

## 快速开始

### 1. 克隆仓库

```bash
git clone git@github.com:hurricane5250/apifox-check-virus-0304.git
cd apifox-check-virus-0304
```

### 2. 直接运行

```bash
python3 detect_apifox_compromise.py
```

### 3. JSON 输出

```bash
python3 detect_apifox_compromise.py --json
```

### 4. 只扫描你指定的目录

```bash
python3 detect_apifox_compromise.py --no-default-roots --root "/path/to/apifox"
```

### 5. 查看默认会扫描哪些目录

```bash
python3 detect_apifox_compromise.py --list-default-roots
```

## 常用参数

```text
--root                 额外指定扫描目录，可重复传入
--no-default-roots     不扫描默认目录，只扫描 --root
--max-file-size-mb     限制单文件最大扫描大小，默认 32MB
--json                 输出 JSON
--list-default-roots   仅打印默认扫描目录
```

## 退出码

- `0`：未发现本地 IOC
- `1`：发现可疑或中危痕迹
- `2`：发现高危 IOC，建议按中招处理

## 输出说明

脚本输出主要包含：

- 实际扫描了哪些根目录
- 找到了哪些 Apifox 本地目录
- 扫描文件数量
- 命中的 IOC
- 命中文件列表
- 风险分数
- 风险结论

结论大致分为：

- `未发现本地 IOC`
- `可疑`
- `中危`
- `高危`

## 重要说明

这个脚本只能证明“当前本地还能否找到残留痕迹”，不能证明“这台机器一定没有中招”。

以下情况可能导致漏报：

- Apifox 已重装、更新或清理缓存
- 系统或用户目录已清理
- 恶意代码只在内存执行，未留下足够磁盘痕迹
- 数据目录位置被修改，但扫描时没有通过 `--root` 指定

如果你在受影响时间窗内运行过 Apifox 桌面端，即使脚本未发现 IOC，也建议至少评估是否需要轮换高价值凭证。

## 建议处置

如果命中高危 IOC，建议至少执行以下动作：

- 立即停用 Apifox 桌面端
- 轮换 SSH 密钥
- 吊销 Git 平台访问令牌
- 轮换 Kubernetes 凭证
- 轮换 npm token
- 检查 Shell 历史中泄露的密钥、密码、API Key
- 审查服务器 SSH 登录日志和内部系统访问日志

## 适用场景

适合：

- 个人开发者自查
- 团队内部批量排查
- 安全部门做轻量本地 IOC 扫描
- 在 CI / 自动化脚本里作为退出码判断

不适合：

- 代替专业取证
- 代替杀毒或 EDR
- 证明主机绝对安全

## 参考来源

- [Apifox 供应链投毒攻击技术分析](https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/)
- [Apifox 官方文档：本地目录路径参考](https://docs.apifox.com/doc-5220271)

## 免责声明

本项目是基于公开信息整理的社区自查工具，不代表官方结论，也不能替代完整的安全事件响应与主机取证流程。
