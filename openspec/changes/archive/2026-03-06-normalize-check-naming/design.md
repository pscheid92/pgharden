## Context

Check structs use inconsistent naming: `check51` vs `check5_2` vs `check4_3` vs `check3120`. This makes the codebase harder to navigate.

## Goals / Non-Goals

**Goals:**
- All check structs follow a single naming convention
- Renames are mechanical with no logic changes

**Non-Goals:**
- Renaming packages or files
- Changing check IDs or behavior

## Decisions

1. **Convention: `checkX_Y` with underscores between all numeric segments**: e.g., `check5_1`, `check5_2`, `check3_1_12`, `check4_10`. This mirrors the dotted check ID format and is the most readable.

2. **Apply across all section files**: All 8 section files get updated.

## Risks / Trade-offs

- Pure rename refactor — risk is near zero. No exported symbols change.
- This should be done after the `extract-check-helper` change, since that change will delete many of the structs being renamed.
