import type { DashboardTheme } from "./types";

const DEFAULT_STATUS_COLORS = {
  destructive: "#fb2c36",
  success: "#4ade80",
  warning: "#ffbd38",
} as const;

interface Rgb {
  b: number;
  g: number;
  r: number;
}

export interface SemanticThemeColors {
  secondary: string;
  status: Record<keyof typeof DEFAULT_STATUS_COLORS, string>;
  tertiary: string;
}

function parseHex(value: string): Rgb {
  const hex = value.trim().replace(/^#/, "");
  const normalized =
    hex.length === 3
      ? hex
          .split("")
          .map((part) => `${part}${part}`)
          .join("")
      : hex;
  if (!/^[0-9a-f]{6}$/i.test(normalized)) {
    throw new Error(`Expected a 3- or 6-digit hex color, received ${value}`);
  }
  return {
    r: Number.parseInt(normalized.slice(0, 2), 16),
    g: Number.parseInt(normalized.slice(2, 4), 16),
    b: Number.parseInt(normalized.slice(4, 6), 16),
  };
}

function toHex({ r, g, b }: Rgb): string {
  return `#${[r, g, b]
    .map((channel) => Math.round(channel).toString(16).padStart(2, "0"))
    .join("")}`;
}

export function mixHex(
  foreground: string,
  background: string,
  amount: number,
): string {
  const fg = parseHex(foreground);
  const bg = parseHex(background);
  return toHex({
    r: fg.r * amount + bg.r * (1 - amount),
    g: fg.g * amount + bg.g * (1 - amount),
    b: fg.b * amount + bg.b * (1 - amount),
  });
}

function relativeLuminance(value: string): number {
  const { r, g, b } = parseHex(value);
  const linear = (channel: number) => {
    const srgb = channel / 255;
    return srgb <= 0.04045
      ? srgb / 12.92
      : ((srgb + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
}

export function contrastRatio(first: string, second: string): number {
  const lighter = Math.max(relativeLuminance(first), relativeLuminance(second));
  const darker = Math.min(relativeLuminance(first), relativeLuminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

function ensureContrast(
  color: string,
  background: string,
  target = 4.5,
): string {
  if (contrastRatio(color, background) >= target) return color;

  const candidates = ["#000000", "#ffffff"]
    .map((endpoint) => {
      for (let step = 1; step <= 100; step += 1) {
        const amount = step / 100;
        const candidate = mixHex(endpoint, color, amount);
        if (contrastRatio(candidate, background) >= target) {
          return { amount, color: candidate };
        }
      }
      return { amount: 1, color: endpoint };
    })
    .sort((left, right) => left.amount - right.amount);

  return candidates[0].color;
}

function ensureTintedSurfaceContrast(
  color: string,
  background: string,
  target = 5,
): string {
  const readable = (candidate: string) =>
    contrastRatio(candidate, mixHex(candidate, background, 0.1)) >= target;
  if (readable(color)) return color;

  return ["#000000", "#ffffff"]
    .map((endpoint) => {
      for (let step = 1; step <= 100; step += 1) {
        const amount = step / 100;
        const candidate = mixHex(endpoint, color, amount);
        if (readable(candidate)) return { amount, color: candidate };
      }
      return { amount: 1, color: endpoint };
    })
    .sort((left, right) => left.amount - right.amount)[0].color;
}

function readableLayerColor(
  foreground: string,
  background: string,
  preferredAmount: number,
): string {
  for (let amount = preferredAmount; amount <= 1; amount += 0.01) {
    const candidate = mixHex(foreground, background, amount);
    if (contrastRatio(candidate, background) >= 4.5) return candidate;
  }
  return ensureContrast(foreground, background);
}

export function resolveSemanticThemeColors(
  theme: DashboardTheme,
): SemanticThemeColors {
  const background = theme.palette.background.hex;
  const midground = theme.palette.midground.hex;
  const status = {
    destructive:
      theme.colorOverrides?.destructive ?? DEFAULT_STATUS_COLORS.destructive,
    success: theme.colorOverrides?.success ?? DEFAULT_STATUS_COLORS.success,
    warning: theme.colorOverrides?.warning ?? DEFAULT_STATUS_COLORS.warning,
  };

  return {
    secondary: readableLayerColor(midground, background, 0.8),
    tertiary: readableLayerColor(midground, background, 0.65),
    status: {
      destructive: ensureTintedSurfaceContrast(status.destructive, background),
      success: ensureTintedSurfaceContrast(status.success, background),
      warning: ensureTintedSurfaceContrast(status.warning, background),
    },
  };
}

export function semanticThemeCssVars(
  theme: DashboardTheme,
): Record<string, string> {
  const colors = resolveSemanticThemeColors(theme);
  return {
    "--color-destructive": colors.status.destructive,
    "--color-success": colors.status.success,
    "--color-warning": colors.status.warning,
    "--text-secondary": colors.secondary,
    "--text-tertiary": colors.tertiary,
  };
}
