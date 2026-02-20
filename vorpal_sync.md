# Vorpal Sync Workflow

## Goal
Always keep `https://github.com/min-mwei/codex.git` branch `dev` up to date with `origin/main` from `https://github.com/openai/codex.git`.

## Remote Setup (run once)
```bash
git remote set-url origin https://github.com/openai/codex.git
git remote add fork https://github.com/min-mwei/codex.git 2>/dev/null || true
git remote set-url fork https://github.com/min-mwei/codex.git
git remote -v
```

Expected:
- `origin` -> `https://github.com/openai/codex.git`
- `fork` -> `https://github.com/min-mwei/codex.git`

## Standard Sync + Merge + Push
Run from repo root:

```bash
git checkout dev
git status --short --branch
git fetch origin main
git merge origin/main
git push fork dev:dev
```

## Verify Push
```bash
git log --oneline -n 3 --decorate
git ls-remote --heads fork dev
```

The SHA shown for `refs/heads/dev` on `fork` should match your local `dev` HEAD.

## If Merge Conflicts Happen
1. Resolve conflicts in files.
2. Stage resolved files:
   ```bash
   git add <file1> <file2> ...
   ```
3. Complete merge commit:
   ```bash
   git commit
   ```
4. Push again:
   ```bash
   git push fork dev:dev
   ```

If you need to cancel the in-progress merge:
```bash
git merge --abort
```

## Important Rule
Do **not** push to `origin` (`openai/codex`).  
Always push the updated `dev` branch to `fork` (`min-mwei/codex`).
