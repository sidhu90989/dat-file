#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const TARGET_FILE = path.resolve(process.argv[2] || "0.0627.dat");
const OUTPUT_DIR = path.resolve("analysis_output");
const ASCII_OUT = path.join(OUTPUT_DIR, "strings_output.txt");
const UTF16_OUT = path.join(OUTPUT_DIR, "utf16_strings.txt");
const HEX_OUT = path.join(OUTPUT_DIR, "hex_dump.txt");
const SUMMARY_OUT = path.join(OUTPUT_DIR, "analysis_summary.txt");
const FULL_OUT = path.join(OUTPUT_DIR, "full_analysis.txt");

const SIGNATURES = [
  { name: "PNG", hex: "89504e470d0a1a0a" },
  { name: "JPEG", hex: "ffd8ff" },
  { name: "ZIP", hex: "504b0304" },
  { name: "PDF", hex: "25504446" },
  { name: "SQLITE", hex: "53514c69746520666f726d6174203300" },
  { name: "JSON_OBJECT", hex: "7b" },
  { name: "JSON_ARRAY", hex: "5b" },
];

const BLOCK_SIZES = [256, 512, 1024, 2048, 4096];
const HEX_LINE_BYTES = 16;

function ensureOutputDir() {
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }
}

function readFileBuffer(filePath) {
  return fs.readFileSync(filePath);
}

function toAscii(byte) {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
}

function printPreview(buffer, length) {
  const limit = Math.min(length, buffer.length);
  console.log(`First ${limit} bytes (hex + ascii):`);

  for (let offset = 0; offset < limit; offset += HEX_LINE_BYTES) {
    const slice = buffer.subarray(offset, offset + HEX_LINE_BYTES);
    const hexPairs = slice.toString("hex").match(/.{1,2}/g) || [];
    const hex = hexPairs.join(" ").padEnd(HEX_LINE_BYTES * 3 - 1, " ");
    const ascii = Array.from(slice).map(toAscii).join("");
    const offsetHex = offset.toString(16).padStart(8, "0");
    console.log(`${offsetHex}  ${hex}  |${ascii}|`);
  }
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

function extractUtf16Strings(buffer, minLength) {
  const strings = [];
  let current = [];

  for (let i = 0; i < buffer.length - 1; i += 2) {
    const codeUnit = buffer[i] | (buffer[i + 1] << 8);
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

function scanSignatures(buffer) {
  const hits = [];
  for (const sig of SIGNATURES) {
    const needle = Buffer.from(sig.hex, "hex");
    let index = 0;
    while (index <= buffer.length - needle.length) {
      index = buffer.indexOf(needle, index);
      if (index === -1) {
        break;
      }
      hits.push({ name: sig.name, offset: index });
      index += 1;
    }
  }
  return hits;
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

function entropyInterpretation(entropy) {
  if (entropy >= 7.5) {
    return "High entropy (likely compressed or encrypted).";
  }
  if (entropy >= 6.0) {
    return "Moderate entropy (structured binary or light compression).";
  }
  return "Lower entropy (plain or highly structured data).";
}

function buildSummary(data) {
  const lines = [];
  lines.push("Binary Analysis Summary");
  lines.push("=");
  lines.push("");
  lines.push(`File: ${data.fileName}`);
  lines.push(`Size: ${data.size} bytes`);
  lines.push("");
  lines.push(`Entropy: ${data.entropy.toFixed(3)} bits/byte`);
  lines.push(`Entropy interpretation: ${data.entropyNote}`);
  lines.push("");
  lines.push(`ASCII strings: ${data.asciiCount}`);
  lines.push(`UTF-16 strings: ${data.utf16Count}`);
  lines.push("");
  lines.push("Detected patterns:");
  if (data.signatures.length > 0) {
    for (const hit of data.signatures.slice(0, 20)) {
      lines.push(`- ${hit.name} at offset ${hit.offset}`);
    }
  } else {
    lines.push("- No common file headers detected.");
  }
  lines.push("");
  lines.push("Possible file structure:");
  for (const stat of data.repetitionStats) {
    lines.push(
      `- ${stat.blockSize} bytes: ${stat.repeatedBlocks} repeated blocks out of ${stat.totalBlocks} (unique ${stat.uniqueBlocks})`
    );
  }
  lines.push("");
  lines.push("Compression/encryption likelihood:");
  lines.push(`- ${data.entropyNote}`);
  lines.push("");
  lines.push("General interpretation:");
  lines.push("- If repeating blocks are present, this may be a database-style format.");
  lines.push("- If headers or readable strings are present, content may include embedded metadata.");
  lines.push("- Moderate entropy often indicates structured binary or light compression.");
  lines.push("");
  return lines;
}

function main() {
  if (!fs.existsSync(TARGET_FILE)) {
    console.error(`File not found: ${TARGET_FILE}`);
    process.exit(1);
  }

  ensureOutputDir();

  const buffer = readFileBuffer(TARGET_FILE);
  console.log(`Analyzing: ${TARGET_FILE}`);
  console.log(`Size: ${buffer.length} bytes`);
  console.log("");

  printPreview(buffer, 128);
  console.log("");

  const asciiStrings = extractAsciiStrings(buffer, 4);
  const utf16Strings = extractUtf16Strings(buffer, 4);
  fs.writeFileSync(ASCII_OUT, asciiStrings.join("\n"), "utf8");
  fs.writeFileSync(UTF16_OUT, utf16Strings.join("\n"), "utf8");

  const entropy = estimateEntropy(buffer);
  console.log(`Entropy: ${entropy.toFixed(3)} bits/byte`);
  console.log("");

  const signatures = scanSignatures(buffer);
  const repetitionStats = BLOCK_SIZES.map((size) => detectRepeatingBlocks(buffer, size));

  const hexLines = buildHexDump(buffer);
  fs.writeFileSync(HEX_OUT, hexLines.join("\n"), "utf8");

  const summaryLines = buildSummary({
    fileName: path.basename(TARGET_FILE),
    size: buffer.length,
    entropy,
    entropyNote: entropyInterpretation(entropy),
    asciiCount: asciiStrings.length,
    utf16Count: utf16Strings.length,
    signatures,
    repetitionStats,
  });
  fs.writeFileSync(SUMMARY_OUT, summaryLines.join("\n"), "utf8");

  const fullLines = [];
  fullLines.push("Binary Analysis Full Report");
  fullLines.push("=");
  fullLines.push("");
  fullLines.push("Summary");
  fullLines.push("-");
  fullLines.push(...summaryLines);
  fullLines.push("");
  fullLines.push("Hex Dump");
  fullLines.push("-");
  fullLines.push(...hexLines);
  fullLines.push("");
  fullLines.push("ASCII Strings");
  fullLines.push("-");
  fullLines.push(...asciiStrings);
  fullLines.push("");
  fullLines.push("UTF-16 Strings");
  fullLines.push("-");
  fullLines.push(...utf16Strings);
  fs.writeFileSync(FULL_OUT, fullLines.join("\n"), "utf8");

  console.log(`ASCII strings saved to ${ASCII_OUT}`);
  console.log(`UTF-16 strings saved to ${UTF16_OUT}`);
  console.log(`Hex dump saved to ${HEX_OUT}`);
  console.log(`Summary report saved to ${SUMMARY_OUT}`);
  console.log(`Full report saved to ${FULL_OUT}`);
}

main();
