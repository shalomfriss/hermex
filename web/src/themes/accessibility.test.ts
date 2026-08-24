import { describe, expect, it } from "vitest";

import { BUILTIN_THEMES } from "./presets";
import {
  contrastRatio,
  mixHex,
  resolveSemanticThemeColors,
  semanticThemeCssVars,
} from "./accessibility";

const AA_NORMAL_TEXT_RATIO = 4.5;

describe("dashboard theme accessibility", () => {
  it("keeps secondary and tertiary text at AA contrast in every built-in theme", () => {
    for (const theme of Object.values(BUILTIN_THEMES)) {
      const colors = resolveSemanticThemeColors(theme);
      expect(
        contrastRatio(colors.secondary, theme.palette.background.hex),
        `${theme.name} secondary text`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT_RATIO);
      expect(
        contrastRatio(colors.tertiary, theme.palette.background.hex),
        `${theme.name} tertiary text`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT_RATIO);
    }
  });

  it("keeps status text at AA contrast in every built-in theme", () => {
    for (const theme of Object.values(BUILTIN_THEMES)) {
      const colors = resolveSemanticThemeColors(theme);
      for (const [name, color] of Object.entries(colors.status)) {
        const tintedSurface = mixHex(color, theme.palette.background.hex, 0.1);
        expect(
          contrastRatio(color, tintedSurface),
          `${theme.name} ${name} text on a tinted status surface`,
        ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT_RATIO);
      }
    }
  });

  it("maps accessible semantic colors onto the live dashboard CSS tokens", () => {
    const theme = BUILTIN_THEMES["nous-blue"];
    const colors = resolveSemanticThemeColors(theme);

    expect(semanticThemeCssVars(theme)).toEqual({
      "--color-destructive": colors.status.destructive,
      "--color-success": colors.status.success,
      "--color-warning": colors.status.warning,
      "--text-secondary": colors.secondary,
      "--text-tertiary": colors.tertiary,
    });
  });
});
