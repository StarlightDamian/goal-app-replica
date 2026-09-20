# Contributing

Small, scoped changes are welcome. Describe the observable problem, intended behavior and evidence. For new platform support, distinguish a working adapter from a protocol proposal.

## Local checks

Use Python 3.11+, install `requirements.txt`, and run from the repository root:

```sh
python examples/quickstart.py
python -m unittest discover -s evals -p "test_*.py"
```

Some browser tests require Node.js and a browser. Report skipped tests and missing prerequisites; skipped checks are not proof of browser coverage. For a small change, run the relevant tests first and the repository CI checks before requesting review.

## Pull requests

- Explain what changes for the user and why.
- Add a focused regression test for behavior changes where practical.
- Keep runtime contracts, reference documents and examples consistent.
- Include the commands run, outcomes and any remaining limitations.
- Use synthetic fixtures. Do not commit credentials, cookies, private data, real application captures or assets without redistribution rights.

Use the issue templates for bugs and feature requests. Follow [SECURITY.md](SECURITY.md) for vulnerabilities. Contributions must be compatible with the repository's [MIT license](LICENSE); disclose third-party sources and their notices.

中文：贡献请说明问题、预期行为和验证结果；优先最小改动，并保留协议与示例一致性。测试中使用虚构数据，不提交凭据、真实客户信息或权利不明的素材。浏览器测试跳过时应明确说明。
