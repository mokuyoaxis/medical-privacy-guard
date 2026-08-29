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
```

退出码：`0` = ALLOW 或验证通过的 SANITIZE，`2` = BLOCK，`3` = ASK，`4` = 解析器、配置或内部错误。

报告的风险是输入在转换前的工程风险。即使输入风险为 high 或 critical，只要每个直接标识符都有确定的转换操作，仍可能得到 SANITIZE；只有验证通过的输出可以被外发。

### v0.1 支持范围

- UTF-8 纯文本；
- 确定性检测中国大陆手机号、邮箱、中国居民身份证候选值、精确日期、带标签的患者姓名和病历号、HTTP(S) URL、IPv4 地址、带标签的精确地址，以及基础医疗内容信号；
- REMOVE、MASK、TOKENIZE、日期/位置 GENERALIZE 和 DATE_SHIFT；
- 仅记录元数据的 JSONL 审计。

JSON-like payload、FHIR、DICOM 和任意二进制文件在 v0.1 中尚不支持，并会默认阻止。医疗内容分类只是保守的规则基线，不是完整的医疗 NER，也不能证明数据已经匿名化。

不含直接标识符的医疗内容仍属于敏感数据。在严格 profile 下，它可以留在本地或可信内部环境，但发送给 `EXTERNAL_UNKNOWN` 接收方会返回 `ASK`。调用方不得把声明的用途视为同意；只有经部署机构批准的端点才能使用 `EXTERNAL_APPROVED`。

### 仅使用合成数据

仓库示例和测试使用人工构造的占位符、保留示例域名/私有 IP 地址空间、`SYNTH-*` 标识符和有明确说明的公共校验示例。请勿在 issue、pull request、fixture 或 CI artifact 中提交真实患者记录、生产审计日志、截图、凭据或 token 到原文的映射。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 诚实的能力边界

本项目是隐私工程基础设施，不是法律或合规认证工具。

1. **不是法律意见，也不是 HIPAA/GDPR 认证。** 本工具用于降低意外披露风险，不能替代法律审查、机构政策或正式合规审计。
2. **不保证完全匿名化。** 去标识化只能降低风险，不能消除风险；残留的准标识符在特定条件下仍可能导致重识别。
3. **无法阻止同权限恶意绕过。** 已经能够直接访问原始 PHI 的进程可以跳过 Guard。本工具防范 Agent 和数据管线的意外或非故意披露，不用于防御有意的内部攻击者。
4. **默认 fail-closed。** 无法证明安全时会阻止或请求人工判断，这是设计特性。

---

## 当前状态

- **Phase 0**（骨架与核心类型）：✅ 已完成
- **Phase 1**（文本 MVP 实现）：✅ 已完成
- **v0.1 发布稳定化**（打包与发布门禁测试）：✅ 已完成；等待 CI/版本流程
- **Phase 1.2**（重识别风险强化）：尚未开始
- **Phase 2**（FHIR + MCP）：尚未开始
- **Phase 3**（DICOM）：尚未开始

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。
