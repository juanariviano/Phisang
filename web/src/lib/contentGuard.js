import FILE_EXTENSIONS from '../../../backend/app/file_types.json';

const extensions = new Set(FILE_EXTENSIONS);
export const FILE_MESSAGE = 'Phisang scans webpages, not files. Enter a webpage URL instead.';

export function fileUrlMessage(raw) {
  try {
    raw = raw.trim();
    const url = new URL(/^[a-z][a-z\d+.-]*:/i.test(raw) ? raw : `https://${raw}`);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    // Decode ASCII escapes even when unrelated filename bytes are invalid UTF-8.
    const path = url.pathname.replace(/%([\da-f]{2})/gi, (_, byte) => String.fromCharCode(parseInt(byte, 16)));
    const filename = path.replace(/\/+$/, '').split('/').pop().split(';')[0].toLowerCase();
    return filename.includes('.') && extensions.has(filename.split('.').pop()) ? FILE_MESSAGE : '';
  } catch {
    return ''; // Normal URL validation reports malformed addresses.
  }
}
