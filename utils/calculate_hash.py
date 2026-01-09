import hashlib

CHUNK_SIZE = 1024 * 1024

def calculate_file_hashes(file_path):
    """คำนวณ hash ของไฟล์ (MD5, SHA1, SHA256)"""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

def calculate_hash_from_chunks(chunks_data):
    """คำนวณ SHA256 hash จาก chunks ของไฟล์ที่อัปโหลด"""
    sha256_hash = hashlib.sha256()
    for chunk in chunks_data:
        sha256_hash.update(chunk)
    return sha256_hash.hexdigest()



