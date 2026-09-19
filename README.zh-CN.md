# medical-privacy-guard

**[English](README.md) | 简体中文**

> 医疗数据跨越信任边界之前的本地优先隐私护栏。

---

## 这是什么？

`medical-privacy-guard` 是一层轻量、可嵌入、默认 fail-closed 的策略层，位于医疗数据管线和外部 AI 系统（LLM、MCP 工具、HTTP API）之间。它会在数据离开本地环境之前检测敏感标识符、评估披露风险、尽可能转换载荷、验证结果，并生成可审计的决策。

本项目的部分理念脱胎于更早的 [`agent-guard`](https://github.com/mokuyoaxis/agent-guard) 项目。两者是同系列的独立项目，拥有不同的威胁模型和执行引擎，同时共享一套 Guard 哲学：减少不可逆后果、不确定性越高限制越强、决策明确、全程留有审计记录。

| | `agent-guard` | `medical-privacy-guard` |
|---|---|---|
| **核心关注点** | 破坏性操作 | 敏感信息披露 |
| **目标** | 在损害发生前建立恢复能力 | 在数据外泄前减少、转换或阻止披露 |
| **计划对象** | RecoveryPlan | DisclosurePlan / TransformationPlan |

---

## 快速开始（文本 MVP）

```bash
python -m pip install -e ".[test]"
python -m pytest -q
```

```python
from medical_privacy_guard import Guard

guard = Guard(profile="external-ai-strict")
result = guard.sanitize(
    "患者：测试患者甲，电话 13800000000",
    recipient="external_unknown",
    purpose="EXTERNAL_AI_ASSISTANCE",
)

if result.sanitized_payload is not None:
    payload_to_release = result.sanitized_payload.content
```

CLI：

```bash
medical-privacy-guard inspect note.txt --json
medical-privacy-guard sanitize note.txt -o note.sanitized.txt --audit-dir audit/
medical-privacy-guard benchmark tests/fixtures/synthetic_cn_notes
```

退出码：`0` = ALLOW 或验证通过的 SANITIZE，`2` = BLOCK，`3` = ASK，`4` = 解析器、配置或内部错误。

报告的风险是输入在转换前的工程风险。即使输入风险为 high 或 critical，只要每个直接标识符都有确定的转换操作，仍可能得到 SANITIZE；只有验证通过的输出可以被外发。

### v0.1 / v0.2 已实现能力

- UTF-8 纯文本；
- 确定性检测：中国大陆手机号与固定电话、邮箱、社交账号、居民身份证候选值、精确日期、带标签患者姓名、医护姓名（职称或后缀形式）、病史中提到的家属姓名、病历号/标本号/检查号、HTTP(S) URL、IPv4 地址、带标签精确地址、带标签邮编、医院名称、科室名称、病区、床号、年龄、临床语境下的性别，以及基础医疗内容信号；
- 手机号支持 3-4-4 分组与 ASCII/全角数字；日期支持 1900–2099 年真实日历日期及月日不补零的 YMD/MDY 形式，并保留原始字符跨度；具体边界见 [scope](docs/scope.md)；
- REMOVE、MASK、TOKENIZE、GENERALIZE（日期到月、年龄到年龄段、位置/机构/科室/病区到类型标记）和 DATE_SHIFT；
- 配置后仅记录元数据的 JSONL 审计；
- 评估工具 `benchmark`，基于 175 份合成中文病历——140 份带标识符标注（1474 个 span、24 种类型），35 份不含标识符。预期路径为 **135 SANITIZE、5 ASK、35 ALLOW**，不是 140 份有标注文档全部脱敏放行；有标注和无标注文档都会计入误报。强化后的评测契约包括逐文档生命周期核对、验证失败及审计缺失/损坏门禁，以及严格一对一精确跨度检测指标。历史 overlap 得分不能证明这些更强检查已经通过；基线与验证状态见 [docs/evaluation.md](docs/evaluation.md)。

当前仅支持纯文本。显式声明为非文本类型的 API 载荷返回 BLOCK。CLI 准入检查拒绝已知不支持的扩展名、NUL 等不支持的控制字符及 JSON 容器内容，但不能可靠识别任意伪装格式。使用 `str` 或 `Payload(kind="text")` 的调用方负责只传入纯文本，不能把结构化或二进制数据序列化为文本后交给 Guard。医疗内容分类只是规则基线，不是完整的医疗 NER，也不能证明数据已经匿名化。

不含直接标识符的医疗内容仍属于敏感数据。在严格 profile 下，它可以留在本地或可信内部环境，但发送给 `EXTERNAL_UNKNOWN` 接收方会返回 `ASK`。调用方不得把声明的用途视为同意；只有经部署机构批准的端点才能使用 `EXTERNAL_APPROVED`。

### 尚未实现

- CSV / XLSX
- JSON 载荷遍历
- FHIR
- DICOM
- PDF / DOCX
- MCP 网关
- HTTP 出站代理
- LLM SDK 包装器
- 数据集级重识别风险度量

### 永不承诺

本项目不认证 HIPAA、GDPR、个保法（PIPL）或任何机构合规性；它降低意外披露风险，但不能证明完全匿名化。

### 仅使用合成数据

仓库示例和测试使用人工构造的占位符、保留示例域名/私有 IP 地址空间、`SYNTH-*` 标识符和有明确说明的公共校验示例。请勿在 issue、pull request、fixture 或 CI artifact 中提交真实患者记录、生产审计日志、截图、凭据或 token 到原文的映射。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 诚实的能力边界

本项目是隐私工程基础设施，不是法律或合规认证工具。

1. **不是法律意见，也不是 HIPAA/GDPR 认证。** 本工具用于降低意外披露风险，不能替代法律审查、机构政策或正式合规审计。
2. **不保证完全匿名化。** 去标识化只能降低风险，不能消除风险；残留的准标识符在特定条件下仍可能导致重识别。
3. **无法阻止同权限恶意绕过。** 已经能够直接访问原始 PHI 的进程可以跳过 Guard。本工具防范 Agent 和数据管线的意外或非故意披露，不用于防御有意的内部攻击者。
4. **对已识别的失败采取 fail-closed。** 不支持的声明类型、验证失败或已配置的审计失败会阻止放行；部分 CLI 错误以非零错误退出而非策略判定结束。未被检测到的标识符仍可能通过；没有检测事实不等于证明安全，验证复用同一组检测器也不能消除共同盲区。

---

## 当前状态

采用单一版本编号路线；详细目标与验收标准见 [ROADMAP.md](ROADMAP.md)。

- **v0.1 — 文本核心 MVP**：已实现（基线检测器、决策协议、转换、验证、仅元数据审计）；发布待 CI/版本流程。
- **v0.2 — 中文医疗文本检测与评估体系**：已实现；发布仍待安全加固验证及发布检查。历史 benchmark 结果不代表修复后的验证或发布验收结果。
- **v0.3 — CSV / XLSX / JSON**：尚未开始。
- **v0.4 — LLM SDK wrapper + MCP 网关**：尚未开始。
- **v0.5 — FHIR 最小资源集**：尚未开始。
- **v0.6 — DICOM metadata scanner**：尚未开始。
- **v1.0 — 医疗 AI 出站隐私网关**：目标。

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。
