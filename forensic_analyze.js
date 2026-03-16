#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_TARGET = "0.0627.dat";
const STRINGS_OUTPUT = path.resolve("strings_output.txt");

// Known file signatures (magic numbers) for quick identification.
const SIGNATURES = [
  { name: "PNG", hex: "89504e470d0a1a0a" },
  { name: "JPEG", hex: "ffd8ff" },
  { name: "GIF87a", hex: "474946383761" },
  { name: "GIF89a", hex: "474946383961" },
  { name: "BMP", hex: "424d" },
  { name: "TIFF_LE", hex: "49492a00" },
  { name: "TIFF_BE", hex: "4d4d002a" },
  { name: "ICO", hex: "00000100" },
  { name: "ZIP", hex: "504b0304" },
  { name: "ZIP_EMPTY", hex: "504b0506" },
  { name: "ZIP_SPANNED", hex: "504b0708" },
  { name: "PDF", hex: "25504446" },
  { name: "RAR4", hex: "526172211a07" },
  { name: "RAR5", hex: "526172211a070100" },
  { name: "7Z", hex: "377abcaf271c" },
  { name: "GZIP", hex: "1f8b08" },
  { name: "BZIP2", hex: "425a68" },
  { name: "XZ", hex: "fd377a585a00" },
  { name: "LZ4", hex: "04224d18" },
  { name: "ZSTD", hex: "28b52ffd" },
  { name: "MP3_ID3", hex: "494433" },
  { name: "MP3_FRAME", hex: "fffb" },
  { name: "WAV", hex: "52494646" },
  { name: "AVI", hex: "52494646" },
  { name: "FLAC", hex: "664c6143" },
  { name: "OGG", hex: "4f676753" },
  { name: "FLV", hex: "464c56" },
  { name: "MKV_WEBM", hex: "1a45dfa3" },
  { name: "MP4", hex: "66747970" },
  { name: "ELF", hex: "7f454c46" },
  { name: "EXE_MZ", hex: "4d5a" },
  { name: "PSD", hex: "38425053" },
  { name: "SQLITE", hex: "53514c69746520666f726d6174203300" },
  { name: "XML", hex: "3c3f786d6c" },
  { name: "CAB", hex: "4d534346" },
  { name: "TAR_USTAR", hex: "7573746172" },
];

function parseArgs(argv) {
  const result = {
    targetFile: DEFAULT_TARGET,
    emitJsonOnly: false,
    jsonOutputPath: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === "--json") {
      result.emitJsonOnly = true;
      continue;
    }

    if (arg === "--json-out") {
      result.jsonOutputPath = argv[i + 1] || null;
      i += 1;
      continue;
    }

    if (arg.startsWith("--json-out=")) {
      result.jsonOutputPath = arg.slice("--json-out=".length) || null;
      continue;
    }

    if (arg.startsWith("-")) {
      continue;
    }

    result.targetFile = arg;
  }

  return result;
}

function readFileBuffer(filePath) {
  return fs.readFileSync(filePath);
}

function bufferToHex(buffer, start, length) {
  const slice = buffer.subarray(start, start + length);
  return slice.toString("hex");
}

function printHexPreview(buffer, length) {
  const hex = bufferToHex(buffer, 0, length);
  const pairs = hex.match(/.{1,2}/g) || [];
  const formatted = pairs.join(" ");
  console.log(`First ${length} bytes (hex):`);
  console.log(formatted);
}

function detectSignatures(buffer) {
  const matches = [];
  const fileHex = buffer.toString("hex", 0, Math.min(buffer.length, 64));

  for (const sig of SIGNATURES) {
    if (fileHex.startsWith(sig.hex)) {
      matches.push({ offset: 0, name: sig.name, hex: sig.hex });
    }
  }

  if (buffer.length >= 12) {
    const riff = buffer.toString("ascii", 0, 4);
    if (riff === "RIFF") {
      const riffType = buffer.toString("ascii", 8, 12);
      matches.push({ offset: 0, name: `RIFF_${riffType.trim()}`, hex: "52494646" });
    }
  }

  if (buffer.length >= 8) {
    const ftyp = buffer.toString("ascii", 4, 8);
    if (ftyp === "ftyp") {
      matches.push({ offset: 4, name: "MP4_FTYP", hex: "66747970" });
    }
  }

  return matches;
}

function scanForEmbeddedHeaders(buffer) {
  const results = [];
  const searchHexes = SIGNATURES.map((sig) => ({ ...sig, bytes: Buffer.from(sig.hex, "hex") }));

  for (const sig of searchHexes) {
    const needle = sig.bytes;
    if (needle.length === 0) {
      continue;
    }

    let index = 0;
    while (index <= buffer.length - needle.length) {
      index = buffer.indexOf(needle, index);
      if (index === -1) {
        break;
      }
      results.push({ offset: index, name: sig.name, hex: sig.hex });
      index += 1; // advance by 1 to catch overlapping signatures
    }
  }

  return results;
}

function extractAsciiStrings(buffer, minLength) {
  const strings = [];
  let current = [];

  for (let i = 0; i < buffer.length; i += 1) {
    const byte = buffer[i];
    // Printable ASCII range plus tab/newline/carriage return.
    const isPrintable = (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;

    if (isPrintable) {
      current.push(byte);
    } else {
      if (current.length >= minLength) {
        strings.push(Buffer.from(current).toString("ascii"));
      }
      current = [];
    }
  }

  if (current.length >= minLength) {
    strings.push(Buffer.from(current).toString("ascii"));
  }

  return strings;
}

function estimateEntropy(buffer) {
  const counts = new Array(256).fill(0);
  for (const byte of buffer) {
    counts[byte] += 1;
  }

  let entropy = 0;
  const total = buffer.length;
  for (const count of counts) {
    if (count === 0) {
      continue;
    }
    const p = count / total;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

function summarizeType(matches, embedded, entropy) {
  const candidates = new Set();
  for (const m of matches) {
    candidates.add(m.name);
  }

  const likelyCompressed = entropy >= 7.5;
  const summary = [];

  if (candidates.size > 0) {
    summary.push(`Header matches: ${Array.from(candidates).join(", ")}`);
  } else {
    summary.push("No direct header match found in first bytes.");
  }

  if (embedded.length > 0) {
    summary.push(`Embedded signatures found: ${embedded.length}`);
  } else {
    summary.push("No embedded signatures detected.");
  }

  summary.push(`Entropy estimate: ${entropy.toFixed(3)} bits/byte`);
  summary.push(likelyCompressed ? "High entropy (likely compressed/encrypted)." : "Lower entropy (likely plain or structured data)." );

  return summary;
}

function buildReport(options) {
  const {
    targetFile,
    buffer,
    headerMatches,
    embeddedMatches,
    strings,
    entropy,
    summary,
  } = options;

  return {
    file: targetFile,
    sizeBytes: buffer.length,
    first64Hex: bufferToHex(buffer, 0, Math.min(64, buffer.length)),
    headerMatches,
    embeddedMatches,
    stringsCount: strings.length,
    stringsOutput: STRINGS_OUTPUT,
    entropyBitsPerByte: Number(entropy.toFixed(6)),
    summary,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const targetFile = path.resolve(args.targetFile);

  if (!fs.existsSync(targetFile)) {
    console.error(`File not found: ${targetFile}`);
    process.exit(1);
  }

  const buffer = readFileBuffer(targetFile);
  if (!args.emitJsonOnly) {
    console.log(`Analyzing: ${targetFile}`);
    console.log(`Size: ${buffer.length} bytes`);
    console.log("");
  }

  if (!args.emitJsonOnly) {
    printHexPreview(buffer, 64);
    console.log("");
  }

  const headerMatches = detectSignatures(buffer);
  if (!args.emitJsonOnly) {
    if (headerMatches.length > 0) {
      console.log("Detected header signatures:");
      for (const match of headerMatches) {
        console.log(`- ${match.name} at offset ${match.offset} (hex ${match.hex})`);
      }
    } else {
      console.log("No header signature detected in first 64 bytes.");
    }
    console.log("");
  }

  const embeddedMatches = scanForEmbeddedHeaders(buffer);
  if (!args.emitJsonOnly) {
    if (embeddedMatches.length > 0) {
      console.log("Embedded signatures (first 20 shown):");
      for (const match of embeddedMatches.slice(0, 20)) {
        console.log(`- ${match.name} at offset ${match.offset}`);
      }
    } else {
      console.log("No embedded signatures found.");
    }
    console.log("");
  }

  const strings = extractAsciiStrings(buffer, 4);
  fs.writeFileSync(STRINGS_OUTPUT, strings.join("\n"), "utf8");
  if (!args.emitJsonOnly) {
    console.log(`Extracted ASCII strings: ${strings.length}`);
    console.log(`Saved to: ${STRINGS_OUTPUT}`);
    console.log("");
  }

  const entropy = estimateEntropy(buffer);
  const summary = summarizeType(headerMatches, embeddedMatches, entropy);
  if (!args.emitJsonOnly) {
    console.log("Summary report:");
    for (const line of summary) {
      console.log(`- ${line}`);
    }
  }

  const report = buildReport({
    targetFile,
    buffer,
    headerMatches,
    embeddedMatches,
    strings,
    entropy,
    summary,
  });

  if (args.jsonOutputPath) {
    fs.writeFileSync(path.resolve(args.jsonOutputPath), JSON.stringify(report, null, 2), "utf8");
  }

  if (args.emitJsonOnly) {
    console.log(JSON.stringify(report, null, 2));
  }
}

main();
