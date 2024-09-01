import { type StdioOptions, type IOType, spawn, spawnSync } from 'node:child_process';
import { type Encoding } from 'node:crypto';
import { type Readable, type Writable } from 'node:stream';
import { inspect } from 'node:util';
import { type RequestInfo, type RequestInit, type TSpawnStore } from './vendor-core.js';
import { type Duration, noop, quote } from './util.js';
export interface Shell {
    (pieces: TemplateStringsArray, ...args: any[]): ProcessPromise;
    (opts: Partial<Options>): Shell;
    sync: {
        (pieces: TemplateStringsArray, ...args: any[]): ProcessOutput;
        (opts: Partial<Options>): Shell;
    };
}
declare const processCwd: unique symbol;
declare const syncExec: unique symbol;
export interface Options {
    [processCwd]: string;
    [syncExec]: boolean;
    cwd?: string;
    ac?: AbortController;
    signal?: AbortSignal;
    input?: string | Buffer | Readable | ProcessOutput | ProcessPromise;
    timeout?: Duration;
    timeoutSignal?: string;
    stdio: StdioOptions;
    verbose: boolean;
    sync: boolean;
    env: NodeJS.ProcessEnv;
    shell: string | boolean;
    nothrow: boolean;
    prefix: string;
    postfix: string;
    quote?: typeof quote;
    quiet: boolean;
    detached: boolean;
    preferLocal: boolean;
    spawn: typeof spawn;
    spawnSync: typeof spawnSync;
    store?: TSpawnStore;
    log: typeof log;
    kill: typeof kill;
}
export declare function syncProcessCwd(flag?: boolean): void;
export declare const defaults: Options;
export declare function usePowerShell(): void;
export declare function usePwsh(): void;
export declare function useBash(): void;
export declare const $: Shell & Options;
type Resolve = (out: ProcessOutput) => void;
export declare class ProcessPromise extends Promise<ProcessOutput> {
    private _command;
    private _from;
    private _resolve;
    private _reject;
    private _snapshot;
    private _stdio?;
    private _nothrow?;
    private _quiet?;
    private _verbose?;
    private _timeout?;
    private _timeoutSignal;
    private _resolved;
    private _halted;
    private _piped;
    private _zurk;
    private _output;
    _prerun: typeof noop;
    _postrun: typeof noop;
    _bind(cmd: string, from: string, resolve: Resolve, reject: Resolve, options: Options): void;
    run(): ProcessPromise;
    get child(): import("child_process").ChildProcess | undefined;
    get stdin(): Writable;
    get stdout(): Readable;
    get stderr(): Readable;
    get exitCode(): Promise<number | null>;
    json<T = any>(): Promise<T>;
    text(encoding?: Encoding): Promise<string>;
    lines(): Promise<string[]>;
    buffer(): Promise<Buffer>;
    blob(type?: string): Promise<Blob>;
    then<R = ProcessOutput, E = ProcessOutput>(onfulfilled?: ((value: ProcessOutput) => PromiseLike<R> | R) | undefined | null, onrejected?: ((reason: ProcessOutput) => PromiseLike<E> | E) | undefined | null): Promise<R | E>;
    catch<T = ProcessOutput>(onrejected?: ((reason: ProcessOutput) => PromiseLike<T> | T) | undefined | null): Promise<ProcessOutput | T>;
    pipe(dest: Writable | ProcessPromise): ProcessPromise;
    abort(reason?: string): void;
    get signal(): AbortSignal | undefined;
    kill(signal?: string): Promise<void>;
    stdio(stdin: IOType, stdout?: IOType, stderr?: IOType): ProcessPromise;
    nothrow(): ProcessPromise;
    quiet(v?: boolean): ProcessPromise;
    verbose(v?: boolean): ProcessPromise;
    isQuiet(): boolean;
    isVerbose(): boolean;
    isNothrow(): boolean;
    timeout(d: Duration, signal?: string): ProcessPromise;
    halt(): ProcessPromise;
    isHalted(): boolean;
    get output(): ProcessOutput | null;
}
export declare class ProcessOutput extends Error {
    private readonly _code;
    private readonly _signal;
    private readonly _stdout;
    private readonly _stderr;
    private readonly _combined;
    constructor(code: number | null, signal: NodeJS.Signals | null, stdout: string, stderr: string, combined: string, message: string);
    toString(): string;
    json<T = any>(): T;
    buffer(): Buffer;
    blob(type?: string): import("buffer").Blob;
    text(encoding?: Encoding): string;
    lines(): string[];
    valueOf(): string;
    get stdout(): string;
    get stderr(): string;
    get exitCode(): number | null;
    get signal(): NodeJS.Signals | null;
    static getExitMessage(code: number | null, signal: NodeJS.Signals | null, stderr: string, from: string): string;
    static getErrorMessage(err: NodeJS.ErrnoException, from: string): string;
    [inspect.custom](): string;
}
export declare function within<R>(callback: () => R): R;
export declare function cd(dir: string | ProcessOutput): void;
export declare function kill(pid: number, signal?: string): Promise<void>;
export type LogEntry = {
    verbose?: boolean;
} & ({
    kind: 'cmd';
    cmd: string;
} | {
    kind: 'stdout' | 'stderr';
    data: Buffer;
} | {
    kind: 'cd';
    dir: string;
} | {
    kind: 'fetch';
    url: RequestInfo;
    init?: RequestInit;
} | {
    kind: 'retry';
    error: string;
} | {
    kind: 'custom';
    data: any;
});
export declare function log(entry: LogEntry): void;
export {};
