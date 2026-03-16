#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const TARGET_FILE = path.resolve(process.argv[2] || "0.0627.dat");
const ASCII_OUTPUT = path.resolve("ascii_strings.txt");
const UTF16_OUTPUT = path.resolve("utf16_strings.txt");

// Known file signatures for embedded header scanning.
const SIGNATURES = [
  { name: "PNG", hex: "89504e470d0a1a0a" },
  { name: "JPEG", hex: "ffd8ff" },
  { name: "ZIP", hex: "504b0304" },
  { name: "PDF", hex: "25504446" },
  { name: "SQLITE", hex: "53514c69746520666f726d6174203300" },
];

const BLOCK_SIZES = [256, 512, 1024, 2048, 4096];
const RECORD_SIZE_CANDIDATES = [16, 24, 32, 48, 64, 96, 128, 192, 256, 320, 384, 512, 768, 1024];

const BASE58_REGEX = /\b[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,35}\b/g;
const BECH32_REGEX = /\bbc1[0-9ac-hj-np-z]{11,71}\b/g;
const WIF_REGEX = /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g;

function readFileBuffer(filePath) {
  return fs.readFileSync(filePath);
}

function bufferToHex(buffer, start, length) {
  return buffer.subarray(start, start + length).toString("hex");
}

function hexAsciiView(buffer, start, length) {
  const slice = buffer.subarray(start, start + length);
  const hexPairs = slice.toString("hex").match(/.{1,2}/g) || [];
  const ascii = Array.from(slice)
    .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
    .join("");
  return { hex: hexPairs.join(" "), ascii };
}

function printInitialView(buffer, length) {
  const view = hexAsciiView(buffer, 0, Math.min(length, buffer.length));
  console.log(`First ${Math.min(length, buffer.length)} bytes (hex):`);
  console.log(view.hex);
  console.log(`First ${Math.min(length, buffer.length)} bytes (ascii):`);
  console.log(view.ascii);
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

function scanForPatterns(strings) {
  const base58 = new Set();
  const bech32 = new Set();
  const wif = new Set();

  for (const s of strings) {
    for (const match of s.match(BASE58_REGEX) || []) {
      base58.add(match);
    }
    for (const match of s.match(BECH32_REGEX) || []) {
      bech32.add(match);
    }
    for (const match of s.match(WIF_REGEX) || []) {
      wif.add(match);
    }
  }

  return {
    base58: Array.from(base58),
    bech32: Array.from(bech32),
    wif: Array.from(wif),
  };
}

function scanForEmbeddedHeaders(buffer) {
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

  return results;
}

function tryDecompression(buffer) {
  const windowSize = 4096;
  const step = 1024;
  const maxAttempts = 30;
  const results = [];

  let attempts = 0;
  for (let offset = 0; offset + windowSize <= buffer.length && attempts < maxAttempts; offset += step) {
    const slice = buffer.subarray(offset, offset + windowSize);

    const methods = [
      { name: "zlib", fn: (data) => zlib.inflateSync(data) },
      { name: "gzip", fn: (data) => zlib.gunzipSync(data) },
      { name: "deflate", fn: (data) => zlib.inflateRawSync(data) },
    ];

    for (const method of methods) {
      try {
        const out = method.fn(slice);
        if (out && out.length > 0) {
          results.push({ offset, method: method.name, outputBytes: out.length });
        }
      } catch (error) {
        // Ignore decompression errors; most windows will not be compressed.
      }
    }

    attempts += 1;
  }

  return results;
}

function buildHexDump(buffer, bytesPerLine) {
  const lines = [];
  for (let offset = 0; offset < buffer.length; offset += bytesPerLine) {
    const slice = buffer.subarray(offset, offset + bytesPerLine);
    const hexPairs = slice.toString("hex").match(/.{1,2}/g) || [];
    const hex = hexPairs.join(" ").padEnd(bytesPerLine * 3 - 1, " ");
    const ascii = Array.from(slice)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
      .join("");
    const offsetHex = offset.toString(16).padStart(8, "0");
    lines.push(`${offsetHex}  ${hex}  |${ascii}|`);
  }
  return lines;
}

function readUInt32LE(buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24);
}

function scanIntegerFields(buffer, step) {
  const values = [];
  for (let offset = 0; offset + 4 <= buffer.length; offset += step) {
    const value = readUInt32LE(buffer, offset) >>> 0;
    // Heuristic: values that look like sizes, timestamps, or small counters.
    if (value > 0 && value < 0x01000000) {
      values.push({ offset, value });
    }
  }
  return values;
}

function findLikelyRecordSizes(buffer) {
  const results = [];
  for (const size of RECORD_SIZE_CANDIDATES) {
    let zeroRuns = 0;
    let printableRuns = 0;
    let records = 0;

    for (let offset = 0; offset + size <= buffer.length; offset += size) {
      const slice = buffer.subarray(offset, offset + size);
      records += 1;

      let zeros = 0;
      let printable = 0;
      for (const b of slice) {
        if (b === 0) {
          zeros += 1;
        }
        if (b >= 0x20 && b <= 0x7e) {
          printable += 1;
        }
      }

      if (zeros >= Math.floor(size * 0.25)) {
        zeroRuns += 1;
      }
      if (printable >= Math.floor(size * 0.25)) {
        printableRuns += 1;
      }
    }

    const score = (zeroRuns + printableRuns) / Math.max(records, 1);
    results.push({ size, score, records, zeroRuns, printableRuns });
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, 5);
}

function summarizeRecordStructure(buffer, recordSize, sampleCount) {
  const records = [];
  const maxSamples = Math.min(sampleCount, Math.floor(buffer.length / recordSize));

  for (let index = 0; index < maxSamples; index += 1) {
    const offset = index * recordSize;
    const slice = buffer.subarray(offset, offset + recordSize);
    const fields = [];

    for (let fieldOffset = 0; fieldOffset + 4 <= slice.length; fieldOffset += 4) {
      const value = readUInt32LE(slice, fieldOffset) >>> 0;
      if (value === 0) {
        continue;
      }
      fields.push({ fieldOffset, value });
      if (fields.length >= 6) {
        break;
      }
    }

    records.push({ offset, size: recordSize, fields });
  }

  return records;
}

function mapBinaryStructure(buffer) {
  const integerFields = scanIntegerFields(buffer, 4);
  const likelySizes = findLikelyRecordSizes(buffer);

  const structure = {
    integerFieldSamples: integerFields.slice(0, 20),
    likelyRecordSizes: likelySizes,
    recordSamples: [],
  };

  if (likelySizes.length > 0) {
    const best = likelySizes[0].size;
    structure.recordSamples = summarizeRecordStructure(buffer, best, 5);
  }

  return structure;
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

function buildReport(details) {
  const summary = [];
  summary.push(`Entropy: ${details.entropy.toFixed(3)} bits/byte`);
  summary.push(entropyInterpretation(details.entropy));

  if (details.headerHits.length > 0) {
    summary.push(`Embedded headers detected: ${details.headerHits.length}`);
  } else {
    summary.push("No embedded headers detected.");
  }

  if (details.patterns.base58.length || details.patterns.bech32.length || details.patterns.wif.length) {
    summary.push("Cryptocurrency-like patterns detected in strings.");
  } else {
    summary.push("No obvious cryptocurrency patterns detected.");
  }

  summary.push("Possible structure: review block repetition stats and header offsets.");
  summary.push("Possible format: wallet.dat or database-like file if repetition and SQLite headers align.");
  summary.push("Structure map: review record size candidates and integer field samples.");

  return summary;
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

  printInitialView(buffer, 128);
  console.log("");

  const asciiStrings = extractAsciiStrings(buffer, 4);
  const utf16Strings = extractUtf16Strings(buffer, 4);
  fs.writeFileSync(ASCII_OUTPUT, asciiStrings.join("\n"), "utf8");
  fs.writeFileSync(UTF16_OUTPUT, utf16Strings.join("\n"), "utf8");
  console.log(`ASCII strings: ${asciiStrings.length} saved to ${ASCII_OUTPUT}`);
  console.log(`UTF-16 strings: ${utf16Strings.length} saved to ${UTF16_OUTPUT}`);
  console.log("");

  const entropy = estimateEntropy(buffer);
  console.log(`Entropy: ${entropy.toFixed(3)} bits/byte`);
  console.log(`${entropyInterpretation(entropy)}`);
  console.log("");

  const repetitionStats = BLOCK_SIZES.map((size) => detectRepeatingBlocks(buffer, size));
  console.log("Repeating block analysis:");
  for (const stat of repetitionStats) {
    console.log(
      `- ${stat.blockSize} bytes: ${stat.repeatedBlocks} repeated blocks out of ${stat.totalBlocks} (unique ${stat.uniqueBlocks})`
    );
  }
  console.log("");

  const patterns = scanForPatterns(asciiStrings.concat(utf16Strings));
  console.log("Crypto pattern matches (unique counts):");
  console.log(`- Base58 addresses: ${patterns.base58.length}`);
  console.log(`- Bech32 addresses: ${patterns.bech32.length}`);
  console.log(`- WIF keys: ${patterns.wif.length}`);
  console.log("");

  const decompressionHits = tryDecompression(buffer);
  if (decompressionHits.length > 0) {
    console.log("Possible compressed windows detected (first 10 shown):");
    for (const hit of decompressionHits.slice(0, 10)) {
      console.log(`- Offset ${hit.offset} via ${hit.method}, output ${hit.outputBytes} bytes`);
    }
  } else {
    console.log("No compressed windows detected in sampled ranges.");
  }
  console.log("");

  const headerHits = scanForEmbeddedHeaders(buffer);
  if (headerHits.length > 0) {
    console.log("Embedded headers detected (first 10 shown):");
    for (const hit of headerHits.slice(0, 10)) {
      console.log(`- ${hit.name} at offset ${hit.offset}`);
    }
  } else {
    console.log("No embedded headers detected.");
  }
  console.log("");

  const hexDumpLines = buildHexDump(buffer, 16);
  console.log("Hex dump (first 64 lines):");
  for (const line of hexDumpLines.slice(0, 64)) {
    console.log(line);
  }
  console.log("");

  const structure = mapBinaryStructure(buffer);
  console.log("Structure mapping:");
  if (structure.likelyRecordSizes.length > 0) {
    console.log("Likely record sizes:");
    for (const candidate of structure.likelyRecordSizes) {
      console.log(
        `- ${candidate.size} bytes: score ${candidate.score.toFixed(3)} (records ${candidate.records}, zero-heavy ${candidate.zeroRuns}, printable-heavy ${candidate.printableRuns})`
      );
    }
  } else {
    console.log("No strong record size candidates detected.");
  }

  if (structure.recordSamples.length > 0) {
    console.log("Record samples (offset, size, fieldOffset/value):");
    for (const record of structure.recordSamples) {
      const fields = record.fields
        .map((field) => `${field.fieldOffset}:${field.value}`)
        .join(", ");
      console.log(`- ${record.offset} (${record.size} bytes) -> ${fields || "no non-zero fields"}`);
    }
  }

  if (structure.integerFieldSamples.length > 0) {
    console.log("Integer field samples (offset/value):");
    for (const sample of structure.integerFieldSamples) {
      console.log(`- ${sample.offset}: ${sample.value}`);
    }
  }
  console.log("");

  const report = buildReport({
    entropy,
    headerHits,
    patterns,
  });
  console.log("Final report summary:");
  for (const line of report) {
    console.log(`- ${line}`);
  }
}

main();
