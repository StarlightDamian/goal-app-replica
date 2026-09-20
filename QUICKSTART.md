# Quickstart / 快速开始

## Run a local state demo

Install Python 3.11+ and Git. From a terminal:

```sh
git clone https://github.com/StarlightDamian/goal-app-replica.git
cd goal-app-replica
python -m pip install -r requirements.txt
python examples/quickstart.py
```

Use `python3` if needed. A virtual environment is recommended if your system Python disallows package installation; activate it using your operating system's normal procedure before installing requirements.

The script creates synthetic reference/replica identities and empty target/state directories under a temporary directory, then calls the controller's `start`, `status` and `validate` commands. Successful validation includes:

```json
{"ok": true, "valid": true}
```

This is an excerpt of the expected validation fields, not a stored test result. Paths and additional fields vary. The script removes its temporary workspace when it exits. No real reference application, account, browser or API key is needed. No application is replicated by this demo.

中文：这一步只验证控制器初始化、状态查询和状态校验。示例使用临时目录及虚构身份，退出时清理；不访问真实应用，也不代表复刻或业务验收成功。

## Install as an agent skill

1. Choose the skill directory supported by your agent host. Follow that host's local skill-loading documentation; paths and discovery behavior vary.
2. Create a new `goal-app-replica` folder there. Copy `SKILL.md`, `agents/`, `references/` and `scripts/` from this repository into it. Keep their relative layout. Do not overwrite an existing installation without preserving your changes.
3. Install this repository's `requirements.txt` into the Python environment used to run its scripts. For browser/CDP helpers, also provide Node.js 24+ and a compatible browser/control session.
4. Reload skills using your host's supported mechanism, then ask the agent to use `goal-app-replica`.

This repository supplies a skill and helper scripts; it does not install or configure your agent host or external desktop/mobile control adapters.

中文：将 `SKILL.md`、`agents/`、`references/`、`scripts/` 保持相对结构复制到所用 Agent 支持的技能目录下的 `goal-app-replica` 文件夹。安装 Python 依赖并按宿主机制重新加载。已有技能先保留本地修改，勿直接覆盖。

## Start a real authorized project

Example instruction for your agent; replace the placeholders:

> Use goal-app-replica for my authorized test application. Reference: `<reference identity and entry point>`. Replica code directory: `<directory>`. Scope: `<pages, flows, roles and viewports>`. Fidelity: `<functional, visual or pixel>`. The reference is read-only. Asset rights: `<what I may reuse>`. Required acceptance scenarios: `<scenarios>`. Start a new project only if no matching state exists; otherwise resume it.

The agent must establish project identity, scope and authorization, then capture evidence using available control tools. Choose a persistent workspace for real work. Inspect available commands rather than copying assumed parameters:

```sh
python scripts/replica_ctl.py --help
python scripts/replica_ctl.py start --help
```

Continue with [SKILL.md](SKILL.md), the [runtime protocol](references/runtime-protocol.md), and [control adapters](references/control-adapters.md). The reference and replica need separate sessions and matching evidence contexts. A complete project requires scenario acceptance, gap handling and reproducible evidence.
