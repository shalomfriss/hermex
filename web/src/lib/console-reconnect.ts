type BuildConsoleWsUrl = (
  path: string,
  params?: { profile: string },
) => Promise<string>;

export async function openConsoleSocket<T>(
  buildUrl: BuildConsoleWsUrl,
  createSocket: (url: string) => T,
  profile?: string,
): Promise<T> {
  const params = profile ? { profile } : undefined;
  const url = await buildUrl("/api/console", params);
  return createSocket(url);
}
