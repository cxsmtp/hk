declare const __HAWK_EXTENSION_BUILD_HASH__: string | undefined;

export function getExtensionBuildHash(): string {
  try {
    const value = typeof __HAWK_EXTENSION_BUILD_HASH__ === "string" ? __HAWK_EXTENSION_BUILD_HASH__ : "";
    return value.trim() || "dev";
  } catch {
    return "dev";
  }
}
