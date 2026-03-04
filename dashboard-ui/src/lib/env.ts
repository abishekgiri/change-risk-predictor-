export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

export function optionalEnv(name: string, fallback = ""): string {
  const value = process.env[name];
  return value && value.trim() ? value.trim() : fallback;
}
