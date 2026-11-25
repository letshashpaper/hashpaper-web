/**
 * HashPaper Universal Zero-Knowledge SHA-256 Engine
 * Computes standard UTF-8 SHA-256 hashes strictly inside the user's browser.
 */

const HashPaperCrypto = {
  async hashText(rawText) {
    if (!rawText || typeof rawText !== 'string') {
      throw new Error('Input text cannot be empty.');
    }

    const standardizedText = rawText.replace(/\r\n/g, '\n');
    const encoder = new TextEncoder();
    const byteBuffer = encoder.encode(standardizedText);

    const hashBuffer = await window.crypto.subtle.digest('SHA-256', byteBuffer);
    const hashHex = this.bufferToHex(hashBuffer);

    return {
      hash: hashHex,
      bytes: byteBuffer,
      byteSize: byteBuffer.length
    };
  },

  async hashFile(file) {
    if (!file) {
      throw new Error('No file selected.');
    }

    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashHex = this.bufferToHex(hashBuffer);

    return {
      hash: hashHex,
      fileName: file.name,
      byteSize: arrayBuffer.byteLength
    };
  },

  downloadReferenceFile(byteBuffer, hashHex) {
    const shortHash = hashHex.substring(0, 12).toUpperCase();
    const fileName = `HashPaper_Ref_${shortHash}.txt`;

    const blob = new Blob([byteBuffer], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();

    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  },

  bufferToHex(buffer) {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }
};

window.HashPaperCrypto = HashPaperCrypto;
