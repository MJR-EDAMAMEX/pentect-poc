import { parseNmapOutput } from "./parser";
import { mask } from "./masker";
import type { MaskResult, Mapping, SourceType, MaskOptions } from "./types";
import { DEFAULT_MASK_OPTIONS } from "./types";

export type { MaskResult, Mapping, SourceType, MaskOptions };
export { DEFAULT_MASK_OPTIONS };

export function maskOutput(
  input: string,
  sourceType: SourceType = "generic",
  options: MaskOptions = DEFAULT_MASK_OPTIONS
): MaskResult {
  switch (sourceType) {
    case "nmap": {
      const hosts = parseNmapOutput(input);
      return mask(hosts, input, options);
    }
    case "generic": {
      return mask([], input, options);
    }
  }
}
