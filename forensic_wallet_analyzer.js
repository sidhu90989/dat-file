#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const TARGET_FILE = path.resolve(process.argv[2] || "0.0627.dat");
const OUT_DIR = path.resolve("extracted_files");
const ASCII_OUT = path.resolve("ascii_strings.txt");
const UTF16_OUT = path.resolve("utf16_strings.txt");
const ENTROPY_OUT = path.resolve("entropy_map.txt");
const HEX_DUMP_OUT = path.resolve("hex_dump.txt");
const STRUCTURE_OUT = path.resolve("structure_map.txt");
const STRUCTURE_JSON_OUT = path.resolve("structure_map.json");
const REPORT_OUT = path.resolve("final_analysis_report.txt");

const BLOCK_SIZES = [256, 512, 1024, 2048, 4096];
const RECORD_SIZE_CANDIDATES = [16, 24, 32, 40, 48, 64, 80, 96, 128, 160, 192, 256, 320, 384, 512, 768, 1024];
const ENTROPY_BLOCK = 1024;
const HEX_LINE_BYTES = 16;
const MAX_DECOMPRESS_OUTPUT = 1024 * 1024; // 1 MB safety cap
const MAX_JSON_SCAN = 512 * 1024; // 512 KB per candidate

const SIGNATURES = [
  { name: "PNG", hex: "89504e470d0a1a0a" },
  { name: "JPEG", hex: "ffd8ff" },
  { name: "ZIP", hex: "504b0304" },
  { name: "SQLITE", hex: "53514c69746520666f726d6174203300" },
];

// LevelDB SSTable magic (little-endian) appears near end of tables.
const LEVELDB_SST_MAGIC_HEX = "57fb808b247547db";

const BASE58_REGEX = /\b[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,35}\b/g;
const BECH32_REGEX = /\bbc1[0-9ac-hj-np-z]{11,71}\b/g;
const ETH_REGEX = /\b0x[a-fA-F0-9]{40}\b/g;
const WIF_REGEX = /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g;

// A light heuristic for possible BIP39 patterns: 12 to 24 lowercase words.
const BIP39_REGEX = /\b[a-z]{3,8}(?:\s+[a-z]{3,8}){11,23}\b/g;

function readFileBuffer(filePath) {
  return fs.readFileSync(filePath);
}

function ensureOutDir() {
  if (!fs.existsSync(OUT_DIR)) {
    fs.mkdirSync(OUT_DIR, { recursive: true });
  }
}

function bufferToHex(buffer, start, length) {
  return buffer.subarray(start, start + length).toString("hex");
}

function toAscii(byte) {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
}

function printHeader(buffer) {
  const length = Math.min(256, buffer.length);
  console.log(`First ${length} bytes (hex + ascii):`);

  for (let offset = 0; offset < length; offset += HEX_LINE_BYTES) {
    const slice = buffer.subarray(offset, offset + HEX_LINE_BYTES);
    const hexPairs = slice.toString("hex").match(/.{1,2}/g) || [];
    const hex = hexPairs.join(" ").padEnd(HEX_LINE_BYTES * 3 - 1, " ");
    const ascii = Array.from(slice).map(toAscii).join("");
    const offsetHex = offset.toString(16).padStart(8, "0");
    console.log(`${offsetHex}  ${hex}  |${ascii}|`);
  }
}

function buildHexDump(buffer) {
  const lines = [];
  for (let offset = 0; offset < buffer.length; offset += HEX_LINE_BYTES) {
    const slice = buffer.subarray(offset, offset + HEX_LINE_BYTES);
    const hexPairs = slice.toString("hex").match(/.{1,2}/g) || [];
    const hex = hexPairs.join(" ").padEnd(HEX_LINE_BYTES * 3 - 1, " ");
    const ascii = Array.from(slice).map(toAscii).join("");
    const offsetHex = offset.toString(16).padStart(8, "0");
    lines.push(`${offsetHex}  ${hex}  |${ascii}|`);
  }
  return lines;
}

function extractAsciiStrings(buffer, minLength) {
  const strings = [];
  let current = [];

  for (let i = 0; i < buffer.length; i += 1) {
    const byte = buffer[i];
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

function extractUtf16Strings(buffer, minLength, bigEndian) {
  const strings = [];
  let current = [];

  for (let i = 0; i < buffer.length - 1; i += 2) {
    const codeUnit = bigEndian
      ? (buffer[i] << 8) | buffer[i + 1]
      : buffer[i] | (buffer[i + 1] << 8);
    const isPrintable = codeUnit >= 0x20 && codeUnit <= 0x7e;

    if (isPrintable) {
      current.push(codeUnit);
    } else {
      if (current.length >= minLength) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }

  if (current.length >= minLength) {
    strings.push(String.fromCharCode(...current));
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

function entropyMap(buffer, blockSize) {
  const map = [];
  for (let offset = 0; offset < buffer.length; offset += blockSize) {
    const slice = buffer.subarray(offset, Math.min(buffer.length, offset + blockSize));
    map.push({ offset, entropy: estimateEntropy(slice) });
  }
  return map;
}

function visualizeEntropy(map) {
  const bars = map.map((entry) => {
    const barLength = Math.max(1, Math.round(entry.entropy * 4));
    return `${entry.offset.toString(16).padStart(8, "0")}  ${entry.entropy.toFixed(3)}  ${"#".repeat(barLength)}`;
  });
  return bars;
}

function scanPatterns(strings) {
  const base58 = new Set();
  const bech32 = new Set();
  const eth = new Set();
  const wif = new Set();
  const bip39 = new Set();

  for (const s of strings) {
    for (const match of s.match(BASE58_REGEX) || []) {
      base58.add(match);
    }
    for (const match of s.match(BECH32_REGEX) || []) {
      bech32.add(match);
    }
    for (const match of s.match(ETH_REGEX) || []) {
      eth.add(match);
    }
    for (const match of s.match(WIF_REGEX) || []) {
      wif.add(match);
    }
    for (const match of s.match(BIP39_REGEX) || []) {
      bip39.add(match);
    }
  }

  return {
    base58: Array.from(base58),
    bech32: Array.from(bech32),
    eth: Array.from(eth),
    wif: Array.from(wif),
    bip39: Array.from(bip39),
  };
}

function detectRepeatingBlocks(buffer, blockSize) {
  const blocks = new Map();
  for (let offset = 0; offset + blockSize <= buffer.length; offset += blockSize) {
    const slice = buffer.subarray(offset, offset + blockSize);
    const key = slice.toString("hex");
    blocks.set(key, (blocks.get(key) || 0) + 1);
  }

  let repeatedBlocks = 0;
  for (const count of blocks.values()) {
    if (count > 1) {
      repeatedBlocks += count;
    }
  }

  return {
    blockSize,
    totalBlocks: Math.floor(buffer.length / blockSize),
    uniqueBlocks: blocks.size,
    repeatedBlocks,
  };
}

function scanEmbeddedHeaders(buffer) {
  const results = [];
  for (const sig of SIGNATURES) {
    const needle = Buffer.from(sig.hex, "hex");
    let index = 0;
    while (index <= buffer.length - needle.length) {
      index = buffer.indexOf(needle, index);
      if (index === -1) {
        break;
      }
      results.push({ name: sig.name, offset: index, hex: sig.hex });
      index += 1;
    }
  }

  // LevelDB SSTable magic appears at end of file. Treat as fragment marker.
  const leveldbNeedle = Buffer.from(LEVELDB_SST_MAGIC_HEX, "hex");
  let index = 0;
  while (index <= buffer.length - leveldbNeedle.length) {
    index = buffer.indexOf(leveldbNeedle, index);
    if (index === -1) {
      break;
    }
    results.push({ name: "LEVELDB_SST_MAGIC", offset: index, hex: LEVELDB_SST_MAGIC_HEX });
    index += 1;
  }

  return results;
}

function carveEmbeddedFiles(buffer, hits) {
  ensureOutDir();
  const outputs = [];

  for (let i = 0; i < hits.length; i += 1) {
    const hit = hits[i];
    const next = hits[i + 1];
    const start = hit.offset;
    const end = next ? next.offset : buffer.length;
    const maxLen = Math.min(end - start, 2 * 1024 * 1024); // cap at 2 MB
    const slice = buffer.subarray(start, start + maxLen);

    const fileName = `${hit.name.toLowerCase()}_${start.toString(16)}.bin`;
    const filePath = path.join(OUT_DIR, fileName);
    fs.writeFileSync(filePath, slice);
    outputs.push({ name: hit.name, offset: start, filePath, bytes: slice.length });
  }

  return outputs;
}

function tryDecompression(buffer) {
  ensureOutDir();
  const windowSize = 4096;
  const step = 1024;
  const maxAttempts = 40;
  const results = [];

  let attempts = 0;
  for (let offset = 0; offset + windowSize <= buffer.length && attempts < maxAttempts; offset += step) {
    const slice = buffer.subarray(offset, offset + windowSize);
    const methods = [
      { name: "zlib", fn: (data) => zlib.inflateSync(data) },
      { name: "gzip", fn: (data) => zlib.gunzipSync(data) },
      { name: "deflate", fn: (data) => zlib.inflateRawSync(data) },
      { name: "brotli", fn: (data) => zlib.brotliDecompressSync(data) },
    ];

    for (const method of methods) {
      try {
        const out = method.fn(slice);
        if (out && out.length > 0 && out.length <= MAX_DECOMPRESS_OUTPUT) {
          const fileName = `decompressed_${method.name}_${offset.toString(16)}.bin`;
          const filePath = path.join(OUT_DIR, fileName);
          fs.writeFileSync(filePath, out);
          results.push({ offset, method: method.name, outputBytes: out.length, filePath });
        }
      } catch (error) {
        // Ignore invalid compressed data.
      }
    }

    attempts += 1;
  }

  return results;
}

function tryExtractJson(buffer) {
  ensureOutDir();
  const outputs = [];

  for (let offset = 0; offset < buffer.length; offset += 1) {
    const byte = buffer[offset];
    if (byte !== 0x7b && byte !== 0x5b) {
      continue;
    }

    const limit = Math.min(buffer.length, offset + MAX_JSON_SCAN);
    const slice = buffer.subarray(offset, limit);
    const text = slice.toString("utf8");

    const endIdx = findJsonEnd(text);
    if (endIdx > 0) {
      const jsonText = text.slice(0, endIdx);
      if (isValidJson(jsonText)) {
        const fileName = `json_${offset.toString(16)}.txt`;
        const filePath = path.join(OUT_DIR, fileName);
        fs.writeFileSync(filePath, jsonText, "utf8");
        outputs.push({ offset, filePath, bytes: jsonText.length });
        offset += endIdx;
      }
    }
  }

  return outputs;
}

function findJsonEnd(text) {
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      continue;
    }

    if (ch === "{" || ch === "[") {
      depth += 1;
    } else if (ch === "}" || ch === "]") {
      depth -= 1;
      if (depth === 0) {
        return i + 1;
      }
    }
  }

  return -1;
}

function isValidJson(text) {
  try {
    JSON.parse(text);
    return true;
  } catch (error) {
    return false;
  }
}

function buildOffsetMap(entropyEntries, blockSize) {
  return entropyEntries.map((entry) => {
    let dataType = "unknown";
    if (entry.entropy >= 7.5) {
      dataType = "compressed/encrypted";
    } else if (entry.entropy >= 6.0) {
      dataType = "structured binary";
    } else {
      dataType = "plain/low entropy";
    }

    return {
      offset: entry.offset,
      blockSize,
      entropy: entry.entropy,
      dataType,
    };
  });
}

function saveEntropyMap(entropyEntries) {
  const lines = entropyEntries.map(
    (entry) =>
      `${entry.offset.toString(16).padStart(8, "0")}  ${entry.entropy.toFixed(3)}  ${entry.dataType}`
  );
  fs.writeFileSync(ENTROPY_OUT, lines.join("\n"), "utf8");
}

function saveHexDump(lines) {
  fs.writeFileSync(HEX_DUMP_OUT, lines.join("\n"), "utf8");
}

function readUInt32LE(buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24);
}

function scoreRecordSizes(buffer) {
  const results = [];

  for (const size of RECORD_SIZE_CANDIDATES) {
    let zeroHeavy = 0;
    let asciiHeavy = 0;
    let recordCount = 0;

    for (let offset = 0; offset + size <= buffer.length; offset += size) {
      const slice = buffer.subarray(offset, offset + size);
      recordCount += 1;

      let zeroCount = 0;
      let asciiCount = 0;
      for (const b of slice) {
        if (b === 0) {
          zeroCount += 1;
        }
        if (b >= 0x20 && b <= 0x7e) {
          asciiCount += 1;
        }
      }

      if (zeroCount >= Math.floor(size * 0.25)) {
        zeroHeavy += 1;
      }
      if (asciiCount >= Math.floor(size * 0.25)) {
        asciiHeavy += 1;
      }
    }

    const score = (zeroHeavy + asciiHeavy) / Math.max(recordCount, 1);
    results.push({ size, score, recordCount, zeroHeavy, asciiHeavy });
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, 5);
}

function analyzeFieldPatterns(buffer, recordSize, sampleCount) {
  const maxSamples = Math.min(sampleCount, Math.floor(buffer.length / recordSize));
  const fieldStats = new Map();

  for (let index = 0; index < maxSamples; index += 1) {
    const base = index * recordSize;
    for (let offset = 0; offset + 4 <= recordSize; offset += 4) {
      const value = readUInt32LE(buffer, base + offset) >>> 0;
      if (!fieldStats.has(offset)) {
        fieldStats.set(offset, { zeroCount: 0, smallCount: 0, asciiCount: 0, examples: new Set() });
      }
      const stat = fieldStats.get(offset);
      if (value === 0) {
        stat.zeroCount += 1;
      }
      if (value > 0 && value < 0x00100000) {
        stat.smallCount += 1;
      }

      const bytes = buffer.subarray(base + offset, base + offset + 4);
      const asciiRun = Array.from(bytes).every((b) => b >= 0x20 && b <= 0x7e);
      if (asciiRun) {
        stat.asciiCount += 1;
        stat.examples.add(bytes.toString("ascii"));
      } else if (value !== 0 && stat.examples.size < 3) {
        stat.examples.add(`0x${value.toString(16)}`);
      }
    }
  }

  const fields = [];
  for (const [offset, stat] of fieldStats.entries()) {
    const meaning = [];
    if (stat.zeroCount >= maxSamples * 0.6) {
      meaning.push("padding/unused");
    }
    if (stat.smallCount >= maxSamples * 0.4) {
      meaning.push("small int/length");
    }
    if (stat.asciiCount >= maxSamples * 0.3) {
      meaning.push("ascii tag");
    }
    if (meaning.length === 0) {
      meaning.push("unknown int");
    }

    fields.push({
      offset,
      size: 4,
      meaning: meaning.join(" | "),
      examples: Array.from(stat.examples).slice(0, 3),
    });
  }

  fields.sort((a, b) => a.offset - b.offset);
  return fields;
}

function buildStructureTable(recordSize, fields) {
  const lines = [];
  lines.push(`Record size candidate: ${recordSize} bytes`);
  lines.push("Offset  Size  Meaning                        Examples");
  lines.push("------  ----  ----------------------------  ----------------------------");

  for (const field of fields) {
    const offsetHex = `0x${field.offset.toString(16).padStart(4, "0")}`;
    const sizeStr = `${field.size}`.padStart(4, " ");
    const meaning = field.meaning.padEnd(28, " ");
    const examples = field.examples.join(", ");
    lines.push(`${offsetHex}  ${sizeStr}  ${meaning}  ${examples}`);
  }

  return lines;
}

function saveStructureMap(lines) {
  fs.writeFileSync(STRUCTURE_OUT, lines.join("\n"), "utf8");
}

function saveStructureJson(payload) {
  fs.writeFileSync(STRUCTURE_JSON_OUT, JSON.stringify(payload, null, 2), "utf8");
}

function buildReport(data) {
  const lines = [];
  lines.push("Forensic Wallet Analysis Report");
  lines.push("=");
  lines.push("");
  lines.push(`Target: ${data.targetFile}`);
  lines.push(`Size: ${data.size} bytes`);
  lines.push("");

  lines.push("Entropy Summary:");
  lines.push(`- Global entropy: ${data.globalEntropy.toFixed(3)} bits/byte`);
  lines.push(`- Interpretation: ${data.entropyNote}`);
  lines.push("");

  lines.push("Pattern Matches:");
  lines.push(`- Base58 addresses: ${data.patterns.base58.length}`);
  lines.push(`- Bech32 addresses: ${data.patterns.bech32.length}`);
  lines.push(`- Ethereum addresses: ${data.patterns.eth.length}`);
  lines.push(`- WIF private keys: ${data.patterns.wif.length}`);
  lines.push(`- BIP39-like phrases: ${data.patterns.bip39.length}`);
  lines.push("");

  lines.push("Compression Detection:");
  lines.push(`- Decompressed blocks: ${data.decompressionHits.length}`);
  lines.push("");

  lines.push("Embedded Artifacts:");
  lines.push(`- Headers detected: ${data.headerHits.length}`);
  lines.push(`- Carved artifacts: ${data.carved.length}`);
  lines.push(`- JSON fragments: ${data.jsonFragments.length}`);
  lines.push("");

  lines.push("Block Structure Analysis:");
  for (const stat of data.repetitionStats) {
    lines.push(
      `- ${stat.blockSize} bytes: ${stat.repeatedBlocks} repeated blocks out of ${stat.totalBlocks} (unique ${stat.uniqueBlocks})`
    );
  }
  lines.push("");

  lines.push("Possible Wallet/Database Notes:");
  lines.push("- Review entropy map for structured vs compressed regions.");
  lines.push("- Repeating block sizes can suggest database pages.");
  lines.push("- Carved artifacts and string patterns can indicate wallet formats.");
  lines.push("- Structure map highlights likely record sizes and integer fields.");
  lines.push("");

  return lines;
}

function entropyInterpretation(entropy) {
  if (entropy >= 7.5) {
    return "High entropy (likely compressed or encrypted).";
  }
  if (entropy >= 6.0) {
    return "Moderate entropy (structured binary or light compression).";
  }
  return "Lower entropy (plain or highly structured data).";
}

function main() {
  if (!fs.existsSync(TARGET_FILE)) {
    console.error(`File not found: ${TARGET_FILE}`);
    process.exit(1);
  }

  const buffer = readFileBuffer(TARGET_FILE);
  console.log(`Analyzing: ${TARGET_FILE}`);
  console.log(`Size: ${buffer.length} bytes`);
  console.log("");

  printHeader(buffer);
  console.log("");

  const asciiStrings = extractAsciiStrings(buffer, 4);
  const utf16LeStrings = extractUtf16Strings(buffer, 4, false);
  const utf16BeStrings = extractUtf16Strings(buffer, 4, true);
  const utf16Combined = utf16LeStrings.concat(utf16BeStrings);

  fs.writeFileSync(ASCII_OUT, asciiStrings.join("\n"), "utf8");
  fs.writeFileSync(UTF16_OUT, utf16Combined.join("\n"), "utf8");

  const patterns = scanPatterns(asciiStrings.concat(utf16Combined));

  const globalEntropy = estimateEntropy(buffer);
  const entropyEntries = entropyMap(buffer, ENTROPY_BLOCK);
  const entropyView = visualizeEntropy(entropyEntries);
  const offsetMap = buildOffsetMap(entropyEntries, ENTROPY_BLOCK);
  saveEntropyMap(offsetMap);

  const hexDumpLines = buildHexDump(buffer);
  saveHexDump(hexDumpLines);

  const headerHits = scanEmbeddedHeaders(buffer);
  const carved = carveEmbeddedFiles(buffer, headerHits);

  const jsonFragments = tryExtractJson(buffer);
  const decompressionHits = tryDecompression(buffer);

  const repetitionStats = BLOCK_SIZES.map((size) => detectRepeatingBlocks(buffer, size));

  const recordCandidates = scoreRecordSizes(buffer);
  const bestRecordSize = recordCandidates.length > 0 ? recordCandidates[0].size : null;
  const fieldPatterns = bestRecordSize ? analyzeFieldPatterns(buffer, bestRecordSize, 128) : [];
  const structureLines = bestRecordSize
    ? buildStructureTable(bestRecordSize, fieldPatterns)
    : ["No strong record size candidates detected."];
  saveStructureMap(structureLines);
  saveStructureJson({
    bestRecordSize,
    recordCandidates,
    fields: fieldPatterns,
  });

  console.log("Entropy distribution (1 KB blocks):");
  for (const line of entropyView.slice(0, 48)) {
    console.log(line);
  }
  console.log("");

  console.log(`ASCII strings: ${asciiStrings.length} saved to ${ASCII_OUT}`);
  console.log(`UTF-16 strings: ${utf16Combined.length} saved to ${UTF16_OUT}`);
  console.log(`Entropy map saved to ${ENTROPY_OUT}`);
  console.log(`Hex dump saved to ${HEX_DUMP_OUT}`);
  console.log("");

  console.log("Pattern matches:");
  console.log(`- Base58: ${patterns.base58.length}`);
  console.log(`- Bech32: ${patterns.bech32.length}`);
  console.log(`- Ethereum: ${patterns.eth.length}`);
  console.log(`- WIF: ${patterns.wif.length}`);
  console.log(`- BIP39-like: ${patterns.bip39.length}`);
  console.log("");

  console.log("Embedded artifacts:");
  console.log(`- Headers detected: ${headerHits.length}`);
  console.log(`- Carved files: ${carved.length}`);
  console.log(`- JSON fragments: ${jsonFragments.length}`);
  console.log(`- Decompressed blocks: ${decompressionHits.length}`);
  console.log("");

  console.log("Structure map summary:");
  if (bestRecordSize) {
    console.log(`- Best record size candidate: ${bestRecordSize} bytes`);
    console.log(`- Field entries: ${fieldPatterns.length}`);
  } else {
    console.log("- No strong record size candidate found.");
  }
  console.log(`- Structure map saved to ${STRUCTURE_OUT}`);
  console.log(`- Structure JSON saved to ${STRUCTURE_JSON_OUT}`);
  console.log("");

  const reportLines = buildReport({
    targetFile: TARGET_FILE,
    size: buffer.length,
    globalEntropy,
    entropyNote: entropyInterpretation(globalEntropy),
    patterns,
    decompressionHits,
    headerHits,
    carved,
    jsonFragments,
    repetitionStats,
  });
  fs.writeFileSync(REPORT_OUT, reportLines.join("\n"), "utf8");
  console.log(`Final report saved to ${REPORT_OUT}`);
}

main();
