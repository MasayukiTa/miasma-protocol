/* tslint:disable */
/* eslint-disable */

/**
 * Dissolve binary data into shares.
 * Returns JSON: { mid, shares, data_shards, total_shards }
 */
export function dissolve_bytes(data: Uint8Array, k: number, n: number): string;

/**
 * Dissolve text content into shares.
 * Returns JSON: { mid, shares, data_shards, total_shards }
 */
export function dissolve_text(plaintext: string, k: number, n: number): string;

/**
 * Get the protocol version string.
 */
export function protocol_version(): string;

/**
 * Retrieve content from shares JSON.
 * shares_json: JSON array of ShareJson objects.
 * Returns the reconstructed bytes.
 */
export function retrieve_from_shares(mid_str: string, shares_json: string, k: number, n: number): Uint8Array;

/**
 * Verify a single share against a MID.
 */
export function verify_share(share_json: string, mid_str: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly dissolve_bytes: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly dissolve_text: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly protocol_version: () => [number, number];
    readonly retrieve_from_shares: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verify_share: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
