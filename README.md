自动化证书注册上线后，一把私钥对应的请求被批了两次，另一个请求却没做挑战就签发了：请求自签不校验，伪造请求被接受；摘要只取主体不含公钥，换密钥仍命中同一幂等键；挑战不绑定摘要，任意挑战可用于任意请求；挑战校验不检查过期时间；策略只校验主体白名单，密钥用途不限；有效期上限不校验，可签发十年期证书；幂等判定只查已签发记录不查进行中记录，并发重复签发；拒绝后不记录状态，同一请求可再次申请成功；批量处理复用挑战，第二个请求沿用第一个请求的挑战；签发不记录请求摘要，无法审计重复申请。enroll/issue.py 是核心，tests/test_issue.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

难度说明：本题是高难度安全 Bugfix 题。注册服务同时承担请求认证、挑战签发、策略批准、幂等控制和拒绝留痕，任何一处状态顺序错误都会导致重复签发、跨请求重放或拒绝后复活。实现必须完全离线，不依赖第三方库。

运行方式：在仓库根目录执行 python -m pytest tests -q。初始预期恰好 15 failed，0 error，15 条失败全部由 NotImplementedError 引起。修复完成后预期 15 passed。自检时请确认失败数量与异常类型，不要只看退出码。

数据模型

CSR：映射或 JSON 文本，字段为 subject、public_key、extensions、validity_days、signature。extensions 至少包含 key_usage 列表。subject 和 public_key 为非空字符串，validity_days 为正整数。

签名：对 subject、public_key、extensions、validity_days 四个语义字段做规范化 JSON 编码，然后使用 signing_key 计算 HMAC-SHA256，输出小写十六进制。规范化 JSON 的规则是对象键排序、分隔符为逗号和冒号、没有多余空格、编码为 UTF-8。signature 字段本身不参与签名输入。

请求摘要：对同样的四个语义字段做规范化 JSON 编码，计算 SHA-256，输出小写十六进制。摘要必须包含 public_key 和 extensions，不能只取 subject；摘要不包含 signature，因此同一请求重新签名后仍应命中同一幂等键。

store：包含 signing_key、challenges、issued、in_progress、rejected、certificates、next_serial。challenges 以 nonce 为键；issued 和 rejected 以请求摘要为键；certificates 以序列号为键；next_serial 从 1000 开始。

challenge：包含 nonce、digest、issued_at、expires_at、used。expires_at 等于签发时刻加 ttl。只有 now 严格小于 expires_at 且 used 为假时挑战仍然有效。

policy：包含 allowed_subjects、allowed_key_usages、max_validity_days、challenge_ttl。subject 必须在白名单中；key_usage 至少有一项且每一项都在允许列表中；validity_days 必须介于 1 和 max_validity_days 之间，包含边界。

issue 的返回：status 为 issued、rejected 或 in_progress。issued 还包含 serial、digest、replayed；rejected 还包含 digest、reason，reason 为 signature、policy 或 challenge；in_progress 包含 digest。首次签发 replayed 为假，重复提交已完成请求返回原序列号且 replayed 为真。被策略或挑战拒绝的摘要写入 rejected，之后即使策略放宽也不能再次签发。签名失败只拒绝本次请求，不污染拒绝表。

enroll_batch：requests 是映射序列，每一项包含 csr 和 store。批次为每一项单独计算摘要并签发全新挑战，不能复用上一项的挑战；一项被拒绝不能中断或影响后续项。返回 results、issued、rejected，results 中每一项是 issue 的返回并额外带有 challenge 的 nonce。

8 个桩

parse_csr：解析并规范化 CSR。
verify_csr_signature：校验请求自签，必须使用恒定时间比较。
request_digest：计算请求摘要，作为幂等键和挑战绑定值。
issue_challenge：签发绑定摘要且带过期时间的挑战。
check_challenge：检查挑战与摘要匹配且未过期、未使用。
policy_allows：检查主体白名单、密钥用途和有效期上限。
issue：完成签名校验、策略批准、挑战校验、幂等签发和拒绝留痕。
enroll_batch：逐项独立处理批量请求。

字段表

字段          值
安全          安全
分类          漏洞检测与攻防
类型          Bugfix
语言与框架    Python 3, pytest
依赖          无外部依赖

tests 与仓库约束

tests 目录不可修改，测试文件名和 15 条用例均为验收标准。只能修改 src/enroll/issue.py 中的 8 个桩，不要改测试来规避断言。__init__.py 只作为包标记，不承载实现。实现文件里应恰好保留 8 个函数桩，修复时逐个替换函数体。

仓库采用 src 布局。pyproject.toml 只包含项目元数据和 pytest 配置，其中 tool.pytest.ini_options 把 pythonpath 设为 src，因此测试可以直接导入 enroll.issue，不需要 conftest.py，也不需要安装项目或联网。测试路径由 testpaths 指定为 tests。不要新增运行时依赖。

仓库结构

sec-cert-enroll/
  README.md
  pyproject.toml
  src/
    enroll/
      __init__.py
      issue.py
  tests/
    test_issue.py

验收锚点：同一请求重复提交返回同一序列号且只落一张证书；挑战必须绑定请求摘要，换请求或篡改挑战字段都不能通过；策略不允许时不得签发；策略拒绝后即使放宽策略也不能复活；批量处理中每个请求必须拿到独立挑战。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

