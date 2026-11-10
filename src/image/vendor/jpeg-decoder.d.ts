interface JPEGComponent {
  scaleX: number; scaleY: number;
  quantizationTable: Int32Array;
  blocks: Int32Array[][];
}
export default function decode(bytes: Uint8Array, options: {
  coefficientsOnly: true; useTArray: true; tolerantDecoding: false;
  maxResolutionInMP: number; maxMemoryUsageInMB: number;
}): { width: number; height: number; components: JPEGComponent[]; allocatedBlockBytes: number };
