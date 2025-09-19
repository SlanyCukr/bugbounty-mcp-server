# AGENTS.md

This file provides guidance to AI coding agents (e.g., Claude Code, OpenAI-based assistants) when working with code in this repository.

## Project Overview

This is a Bug Bounty MCP Server focused solely on bug bounty hunting workflows and REST API endpoints. It provides an MCP (Model Context Protocol) interface for AI agents to interact with bug bounty tools and workflows.

## Architecture

The project has files in `src/` for the main server code.

## Dependencies & Environment Management (uv)
- **Project Management**: Uses `uv` exclusively for fast, reliable dependency management
- **Configuration**: Dependencies defined in `pyproject.toml`, locked in `uv.lock`
- **Virtual Environment**: Automatically managed by uv at `.venv/`
- **Installation**: `uv sync` - Install/update dependencies
- **Development Dependencies**: `uv sync --dev` - Include development tools (pre-commit, ruff, etc.)
- **Running Commands**: `uv run <command>` - Execute commands within the project environment

### Package Management Commands
- **Add packages**: `uv add <package>` - Install new dependencies
- **Remove packages**: `uv remove <package>` - Remove dependencies
- **Never use**: pip, pip-tools, poetry, or conda directly for dependency management

### Running Python Code
- **Scripts**: `uv run <script-name>.py` - Run Python scripts
- **Tools**: `uv run ruff` - Run Python tools
- **REPL**: `uv run python` - Launch Python interactive shell

### PEP 723 Inline Metadata Scripts
- **Run scripts**: `uv run script.py` - Execute scripts with inline dependencies
- **Add deps**: `uv add package-name --script script.py` - Add dependencies to script
- **Remove deps**: `uv remove package-name --script script.py` - Remove dependencies from script

## Common Development Commands

### Installing Dependencies

Install all dependencies:
```bash
uv sync
```

Install with development dependencies:
```bash
uv sync --dev
```

### Starting the Servers

**REST API Server:**
```bash
uv run -m src.rest_api_server
```

**With environment variables:**
```bash
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run -m src.rest_api_server
```

**MCP Server:**
```bash
uv run -m src.mcp_server
```

## CRITICAL: Use ripgrep, not grep

NEVER use grep for project-wide searches (slow, ignores .gitignore). ALWAYS use rg.

- `rg "pattern"` — search content
- `rg --files | rg "name"` — find files
- `rg -t python "def"` — language filters

## File finding

- Prefer `fd` (or `fdfind` on Debian/Ubuntu). Respects .gitignore.

## JSON

- Use `jq` for parsing and transformations.

## Agent Instructions

- Replace commands: grep→rg, find→rg --files/fd, ls -R→rg --files, cat|grep→rg pattern file
- Cap reads at 250 lines; prefer `rg -n -A 3 -B 3` for context
- Use `jq` for JSON instead of regex

## Subagents MCP Server

A dedicated Codex sub-agents MCP server lives at `~/Documents/MCP_servers/codex-subagents-mcp`. It exposes the `delegate`, `list_agents`, and `validate_agents` tools and loads personas from `agents/*.md` (e.g., `orchestrator`, `review`, `debugger`, `security`).

- Always start coordination by delegating to the orchestrator agent so it can route follow-up work:
  - `subagents.delegate(agent="orchestrator", task="<goal>")`
- Invoke specialists the orchestrator recommends (or you choose) for implementation, documentation, or audits.
- Run `tools.call name=list_agents` or `tools.call name=validate_agents` at session start if you need a roster refresher.
- Custom slash commands (`/orchestrate-plan`, `/orchestrate-implement`, `/orchestrate-review`) drop canonical prompts straight into the session.

## Agent Orchestration (Claude Code)

This repo prefers a senior–engineer orchestration model: you supervise; Claude Code subagents execute focused work via non-interactive runs.

- Subagent mentions: refer to agents as `@implementor`, `@codebase-research-analyst`, `@root-cause-analyzer`, etc. Do not append `.md`.
- Non-interactive runs: use `claude -p` to spawn subagent tasks that return results and exit.
- Output contract for implementation: request an `apply_patch`-style envelope only, followed by a tiny "Verify" checklist. Keep prose minimal.
- Parallelization: for independent tasks (e.g., API audit vs MCP audit), spawn multiple agents in parallel, each with a narrow scope and explicit expected output.
- Chunk investigations: avoid single, sweeping prompts over the entire codebase. Split by feature (e.g., auth, jobs, MCP tools) to keep prompts within context and speed up iteration.
- Extend before create: prefer editing existing files and following neighboring patterns over new files unless necessary.
- Implementation only on request: analyze first; modify code only when the task explicitly asks to build/fix.

### Prompt Structure (concise)

- Context: the area of the repo (e.g., `src/` modules, specific files/patterns to follow).
- Task: the minimal change or investigation goal.
- Output: strict format (patch-only or short structured summary + file paths).
- Verify: short command list (e.g., `uv sync`, `uv run -m src.rest_api_server`, `uv run -m src.mcp_server`).

### Typical Flows

- Research: `@codebase-research-analyst` to map patterns and key files before implementation.
- Implement: `@implementor` to produce minimal patch envelopes that match existing conventions.
- Root cause + fix: `@root-cause-analyzer` to diagnose and return the smallest safe fix.
- Docs/commit: `@docs-git-commiter` to produce concise commit message + CHANGELOG entry.

### Review & Validation

- Supervise every deliverable: skim for scope creep, consistency with patterns, and safety.
- Validate locally using `uv` commands; prefer targeted checks over full sweeps.
- If adjustments are needed, send a surgical follow-up prompt to the same subagent.

## Deterministic Changes via Git Worktrees

For non-trivial edits, prefer executing changes inside a temporary git worktree and returning a diff, so outputs are deterministic and reproducible.

Default for code changes (implementor/root-cause): use this flow.

Recommended flow for subagents:

- Determine repo root: `REPO=$(git rev-parse --show-toplevel)`
- Create worktree path: `WT_NAME="agent-$(date +%Y%m%d-%H%M%S)"` and `WT_DIR="$REPO/.worktrees/$WT_NAME"`
- Create branch and worktree: `git worktree add -b "$WT_NAME" "$WT_DIR" HEAD`
- Perform changes inside `"$WT_DIR"` only; do not commit unless explicitly requested
- Show changes: `git -C "$WT_DIR" status --porcelain` and `git -C "$WT_DIR" diff --patch`
- Output contract:
  - Include the `git diff` patch (deterministic)
  - Also include an `apply_patch` envelope derived from the actual changed files (optional but preferred for easy application here)
- Cleanup (optional): leave worktree for further tweaks, or remove with `git worktree remove "$WT_DIR"` if asked

Notes:
- Keep worktrees under `./.worktrees/` to avoid clutter; do not nest inside `.git/`
- Never touch unrelated files; keep changes minimal and follow existing patterns
