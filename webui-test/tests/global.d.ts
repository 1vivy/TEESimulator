export {};

declare global {
  var __teesimulatorRkaCallbacks: Record<
    string,
    (errno: number | string, stdout: string, stderr: string) => void
  >;
  var ksu: {
    exec(command: string, options: string, callback: string): Promise<void>;
  };
}
