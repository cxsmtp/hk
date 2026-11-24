declare module "node:crypto" {
  type JsonWebKey = {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };
  type KeyObject = {
    export(options: { format: "jwk" }): JsonWebKey;
  };
  type Hash = {
    update(value: string): Hash;
    digest(encoding: "hex"): string;
  };
  export function createHash(algorithm: string): Hash;
  export function createPublicKey(value: string): KeyObject;
  export function randomUUID(): string;
  export function verify(
    algorithm: string,
    data: Uint8Array,
    key: KeyObject,
    signature: Uint8Array,
  ): boolean;
}

declare module "node:fs/promises" {
  export type Stats = {
    dev: number;
    ino: number;
    mode: number;
    uid: number;
    isDirectory(): boolean;
    isSocket(): boolean;
  };

  export function lstat(path: string): Promise<Stats>;
}

declare module "node:net" {
  export type Socket = {
    destroy(): void;
    setEncoding(encoding: "utf8"): void;
    write(data: string): boolean;
    once(event: string, listener: (...args: unknown[]) => void): Socket;
    on(event: string, listener: (...args: unknown[]) => void): Socket;
  };

  export function createConnection(options: { path: string }): Socket;
}

declare module "node:path" {
  export function dirname(path: string): string;
}

declare const process: {
  arch: string;
  getuid?: () => number;
  pid: number;
  platform: string;
  version: string;
};
