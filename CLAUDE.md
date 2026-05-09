Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.



Tradeoff: These guidelines bias toward caution over speed. For trivial tasks, use judgment.



1\. Think Before Coding

Don't assume. Don't hide confusion. Surface tradeoffs.



Before implementing:



State your assumptions explicitly. If uncertain, ask.

If multiple interpretations exist, present them - don't pick silently.

If a simpler approach exists, say so. Push back when warranted.

If something is unclear, stop. Name what's confusing. Ask.

2\. Simplicity First

Minimum code that solves the problem. Nothing speculative.



No features beyond what was asked.

No abstractions for single-use code.

No "flexibility" or "configurability" that wasn't requested.

No error handling for impossible scenarios.

If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.



3\. Surgical Changes

Touch only what you must. Clean up only your own mess.



When editing existing code:



Don't "improve" adjacent code, comments, or formatting.

Don't refactor things that aren't broken.

Match existing style, even if you'd do it differently.

If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:



Remove imports/variables/functions that YOUR changes made unused.

Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.



4\. Goal-Driven Execution

Define success criteria. Loop until verified.



Transform tasks into verifiable goals:



"Add validation" → "Write tests for invalid inputs, then make them pass"

"Fix the bug" → "Write a test that reproduces it, then make it pass"

"Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:



1\. \[Step] → verify: \[check]

2\. \[Step] → verify: \[check]

3\. \[Step] → verify: \[check]

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.



These guidelines are working if: fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

---

## 项目专属规则

### Git 提交
- 当前仓库远程：
  - GitHub (origin): `https://github.com/1069137617/GoNeo-WAF.git`
  - Gitee (gitee):   `https://gitee.com/mayinuo8394/go-neo-waf.git`
- 每次更新后强制推送双平台：
  ```
  git push --force origin master
  git push --force gitee master
  ```
- **禁止提交**任何技术文档文件（.md 文档、API 文档、设计文档等）
- 禁止提交任何技术文档文件（.md 文档、API 文档、设计文档等）
- 只提交代码和必要的配置文件和README.md
