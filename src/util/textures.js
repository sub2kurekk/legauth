// Validates and sanitizes user-uploaded skin/cape PNGs.
//
// The authlib-injector server spec explicitly warns that unprocessed
// user-uploaded textures can lead to remote code execution or denial of
// service (PNG bombs) on clients that later load them. We therefore:
//   1. Cap the raw upload size before touching it.
//   2. Read only the PNG header (IHDR) to check dimensions BEFORE decoding
//      any pixel data, so a file that lies about being tiny but claims a
//      huge canvas is rejected early.
//   3. Only after that passes, fully decode and re-encode the image with
//      pngjs, which drops any non-image ancillary chunks (metadata,
//      embedded text/data, etc.).

const crypto = require('crypto');
const { PNG } = require('pngjs');

const MAX_UPLOAD_BYTES = 200 * 1024; // skins/capes are a few KB at most
const MAX_DIMENSION = 1024;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function readPngHeader(buffer) {
  if (buffer.length < 33) throw new Error('File is too small to be a valid PNG.');
  if (!buffer.slice(0, 8).equals(PNG_SIGNATURE)) throw new Error('That is not a valid PNG file.');
  const chunkType = buffer.slice(12, 16).toString('ascii');
  if (chunkType !== 'IHDR') throw new Error('Malformed PNG file (missing IHDR).');
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function validateDimensions(type, width, height) {
  if (width <= 0 || height <= 0) throw new Error('Invalid image dimensions.');
  if (width > MAX_DIMENSION || height > MAX_DIMENSION) throw new Error('Image is too large.');
  if (type === 'skin') {
    const ok = width % 64 === 0 && (height % 32 === 0 || height % 64 === 0);
    if (!ok) throw new Error('Skins must be 64 pixels wide, with a height that is a multiple of 32 (e.g. 64x64 or 64x32).');
  } else if (type === 'cape') {
    const okStandard = width % 64 === 0 && height % 32 === 0;
    const okLegacy = width % 22 === 0 && height % 17 === 0;
    if (!okStandard && !okLegacy) throw new Error('Capes must be 64xN (N a multiple of 32) or 22x17.');
  } else {
    throw new Error('Unknown texture type.');
  }
}

async function processTexture(buffer, type) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new Error('No file was uploaded.');
  if (buffer.length > MAX_UPLOAD_BYTES) throw new Error('File is too large (max 200KB).');

  const { width, height } = readPngHeader(buffer);
  validateDimensions(type, width, height);

  // Safe to fully decode now that dimensions are bounded and sane.
  let png;
  try {
    png = PNG.sync.read(buffer, { checkCRC: true });
  } catch (e) {
    throw new Error('Could not decode PNG file: ' + e.message);
  }

  // Re-encoding strips any ancillary chunks (tEXt, unknown/private chunks,
  // etc.) that could otherwise be used to smuggle non-image data.
  const clean = PNG.sync.write(png, { colorType: 6 });
  const hash = crypto.createHash('sha256').update(clean).digest('hex');

  return { data: clean, hash, width: png.width, height: png.height };
}

module.exports = { processTexture, MAX_UPLOAD_BYTES };
