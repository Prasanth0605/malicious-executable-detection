import os
import struct
import hashlib
import math
from collections import Counter

def extract_features(filepath):
    """
    Extract features from an executable file for malware detection.
    This function extracts various static features from the file.
    
    Args:
        filepath: Path to the executable file
    
    Returns:
        List of extracted features
    """
    features = []
    
    try:
        # Read file content
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # 1. File size features
        file_size = os.path.getsize(filepath)
        features.append(file_size)
        features.append(math.log10(file_size + 1))  # Log of file size
        
        # 2. Hash-based features (for fingerprinting)
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        # Convert first 8 chars of hashes to numeric features
        features.append(int(md5_hash[:8], 16) % 1000000)
        features.append(int(sha1_hash[:8], 16) % 1000000)
        
        # 3. Byte distribution features
        byte_counts = Counter(content)
        
        # Entropy calculation
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(content)
            entropy -= probability * math.log2(probability)
        features.append(entropy)
        
        # Statistical features
        byte_values = list(content)
        features.append(sum(byte_values) / len(byte_values))  # Mean
        features.append(max(byte_values))  # Max
        features.append(min(byte_values))  # Min
        
        # Byte frequency features (count of specific byte ranges)
        features.append(sum(1 for b in byte_values if b == 0))  # Null bytes
        features.append(sum(1 for b in byte_values if 32 <= b <= 126))  # Printable ASCII
        features.append(sum(1 for b in byte_values if b >= 128))  # High bytes
        
        # 4. Pattern-based features
        # Count of specific patterns
        features.append(content.count(b'\x00\x00\x00\x00'))  # Null sequences
        features.append(content.count(b'\xFF\xFF\xFF\xFF'))  # FF sequences
        features.append(content.count(b'MZ'))  # DOS header
        features.append(content.count(b'PE'))  # PE header
        
        # 5. Section-based features (simplified)
        # Count certain common strings/patterns
        features.append(content.count(b'.text'))
        features.append(content.count(b'.data'))
        features.append(content.count(b'.rdata'))
        features.append(content.count(b'.rsrc'))
        
        # 6. API/Import related features (string-based)
        suspicious_apis = [
            b'CreateRemoteThread', b'WriteProcessMemory', b'VirtualAllocEx',
            b'OpenProcess', b'GetProcAddress', b'LoadLibrary', b'RegSetValue',
            b'CreateFile', b'WriteFile', b'ReadFile', b'InternetOpen'
        ]
        
        for api in suspicious_apis:
            features.append(content.count(api))
        
        # 7. String-based features
        features.append(content.count(b'http://'))
        features.append(content.count(b'https://'))
        features.append(content.count(b'.exe'))
        features.append(content.count(b'.dll'))
        features.append(content.count(b'temp'))
        features.append(content.count(b'system32'))
        
        # 8. Structural features
        # Ratio of null bytes
        features.append(content.count(b'\x00') / len(content))
        
        # Ratio of printable characters
        printable_count = sum(1 for b in byte_values if 32 <= b <= 126)
        features.append(printable_count / len(content))
        
        # 9. Byte n-gram features (bigrams)
        bigram_counts = {}
        for i in range(len(content) - 1):
            bigram = content[i:i+2]
            bigram_counts[bigram] = bigram_counts.get(bigram, 0) + 1
        
        # Most common bigrams
        if bigram_counts:
            most_common_bigram_freq = max(bigram_counts.values()) / len(content)
            features.append(most_common_bigram_freq)
        else:
            features.append(0)
        
        # 10. PE-specific features (if PE file)
        if content[:2] == b'MZ' and len(content) > 64:
            try:
                # Get PE header offset
                pe_offset = struct.unpack('<I', content[60:64])[0]
                if pe_offset < len(content) - 4:
                    # Check PE signature
                    if content[pe_offset:pe_offset+2] == b'PE':
                        features.append(1)  # Is PE
                        
                        # Extract some PE characteristics
                        if pe_offset + 24 < len(content):
                            characteristics = struct.unpack('<H', content[pe_offset+22:pe_offset+24])[0]
                            features.append(characteristics)
                        else:
                            features.append(0)
                    else:
                        features.append(0)
                        features.append(0)
                else:
                    features.append(0)
                    features.append(0)
            except:
                features.append(0)
                features.append(0)
        else:
            features.append(0)  # Not PE
            features.append(0)
        
        # 11. Additional statistical features
        # Variance approximation
        mean_byte = sum(byte_values) / len(byte_values)
        variance = sum((b - mean_byte) ** 2 for b in byte_values[:10000]) / min(10000, len(byte_values))
        features.append(variance)
        
        # Unique byte ratio
        features.append(len(set(byte_values)) / 256)
        
        # Section count approximation (count of section markers)
        section_markers = [b'.text', b'.data', b'.rdata', b'.rsrc', b'.reloc', b'.idata']
        features.append(sum(1 for marker in section_markers if marker in content))
        
        return features
        
    except Exception as e:
        print(f"Error extracting features from {filepath}: {e}")
        # Return default features (all zeros) in case of error
        return [0] * 50  # Adjust based on total number of features


def get_feature_names():
    """
    Returns the names of all features in order.
    Useful for creating feature dataframes.
    """
    names = [
        'file_size', 'file_size_log',
        'md5_numeric', 'sha1_numeric',
        'entropy', 'byte_mean', 'byte_max', 'byte_min',
        'null_bytes', 'printable_ascii', 'high_bytes',
        'null_sequences', 'ff_sequences', 'mz_count', 'pe_count',
        'text_section', 'data_section', 'rdata_section', 'rsrc_section',
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'OpenProcess', 'GetProcAddress', 'LoadLibrary', 'RegSetValue',
        'CreateFile', 'WriteFile', 'ReadFile', 'InternetOpen',
        'http_count', 'https_count', 'exe_count', 'dll_count',
        'temp_count', 'system32_count',
        'null_ratio', 'printable_ratio',
        'bigram_freq',
        'is_pe', 'pe_characteristics',
        'byte_variance', 'unique_byte_ratio', 'section_count'
    ]
    return names


if __name__ == '__main__':
    # Test feature extraction
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <executable_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)
    
    print(f"Extracting features from: {filepath}")
    features = extract_features(filepath)
    feature_names = get_feature_names()
    
    print(f"\nExtracted {len(features)} features:")
    print("=" * 60)
    for name, value in zip(feature_names, features):
        print(f"{name:30s}: {value}")
    print("=" * 60)
