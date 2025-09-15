"""
File utility functions for the antivirus system.

This module provides functions for file operations, hashing, and metadata extraction.
"""
import os
import io
import hashlib
import magic
import pefile
import zipfile
import tarfile
import gzip
import bz2
import rarfile
import py7zr
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, BinaryIO, Generator

from ..core.config import ScanConfig
from .logger import get_logger

logger = get_logger(__name__)

class FileUtils:
    """Utility class for file operations."""
    
    # File magic instance for MIME type detection
    _file_magic = magic.Magic(mime=True)
    
    @staticmethod
    def calculate_hash(file_path: Union[str, Path], algorithm: str = 'sha256', 
                      chunk_size: int = 65536) -> str:
        """Calculate the hash of a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use (default: sha256)
            chunk_size: Size of chunks to read at a time (default: 64KB)
            
        Returns:
            Hex digest of the file's hash
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hash_func = getattr(hashlib, algorithm.lower(), None)
        if not hash_func:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        h = hash_func()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    
    @classmethod
    def get_file_info(cls, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Get detailed information about a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary containing file metadata
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        stats = file_path.stat()
        
        return {
            'path': str(file_path.absolute()),
            'name': file_path.name,
            'size': stats.st_size,
            'created': stats.st_ctime,
            'modified': stats.st_mtime,
            'accessed': stats.st_atime,
            'permissions': oct(stats.st_mode)[-3:],
            'inode': stats.st_ino,
            'mime_type': cls._file_magic.from_file(str(file_path)),
            'is_symlink': file_path.is_symlink(),
            'is_dir': file_path.is_dir(),
            'is_file': file_path.is_file(),
        }
    
    @staticmethod
    def is_binary(file_path: Union[str, Path]) -> bool:
        """Check if a file is a binary file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file is binary, False otherwise
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if not chunk:  # Empty file
                    return False
                # Check for null bytes in the first chunk
                if b'\x00' in chunk:
                    return True
                # Check for non-printable bytes
                return any(b < 32 and b not in (9, 10, 13) for b in chunk)
        except Exception as e:
            logger.warning(f"Error checking if file is binary: {e}")
            return False
    
    @classmethod
    def extract_pe_metadata(cls, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Extract metadata from a PE (Portable Executable) file.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Dictionary containing PE metadata
        """
        try:
            pe = pefile.PE(str(file_path))
            
            info = {
                'is_pe': True,
                'machine_type': pe.FILE_HEADER.Machine,
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'sections': [],
                'imports': [],
                'exports': [],
                'resources': [],
                'version_info': {},
                'is_dll': pe.is_dll(),
                'is_exe': pe.is_exe(),
                'is_driver': pe.is_driver(),
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'image_base': pe.OPTIONAL_HEADER.ImageBase,
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'suspicious_characteristics': [],
            }
            
            # Extract sections
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy(),
                    'characteristics': section.Characteristics,
                }
                info['sections'].append(section_info)
            
            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        func = imp.name.decode('utf-8', errors='ignore') if imp.name else f'ordinal_{imp.ordinal}'
                        info['imports'].append(f"{dll}.{func}")
            
            # Extract exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        info['exports'].append(exp.name.decode('utf-8', errors='ignore'))
                    else:
                        info['exports'].append(f'ordinal_{exp.ordinal}')
            
            # Extract resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource in resource_id.directory.entries:
                                    try:
                                        offset = resource.data.struct.OffsetToData
                                        size = resource.data.struct.Size
                                        info['resources'].append({
                                            'type': resource_type.name if hasattr(resource_type, 'name') else resource_type.struct.Name,
                                            'id': resource_id.name if hasattr(resource_id, 'name') else resource_id.struct.Name,
                                            'language': resource.name if hasattr(resource, 'name') else resource.struct.Name,
                                            'offset': offset,
                                            'size': size,
                                        })
                                    except Exception as e:
                                        logger.debug(f"Error extracting resource: {e}")
            
            # Extract version info
            if hasattr(pe, 'FileInfo'):
                for fileinfo in pe.FileInfo:
                    if fileinfo.Key == 'StringFileInfo':
                        for st in fileinfo.StringTable:
                            for entry in st.entries.items():
                                info['version_info'][entry[0].decode('utf-8', errors='ignore')] = entry[1].decode('utf-8', errors='ignore')
            
            # Check for suspicious characteristics
            suspicious_flags = [
                ('IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 0x0040),
                ('IMAGE_DLLCHARACTERISTICS_NX_COMPAT', 0x0100),
                ('IMAGE_DLLCHARACTERISTICS_NO_SEH', 0x0400),
                ('IMAGE_DLLCHARACTERISTICS_GUARD_CF', 0x4000),
                ('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', 0x8000),
            ]
            
            for name, flag in suspicious_flags:
                if pe.OPTIONAL_HEADER.DllCharacteristics & flag:
                    info['suspicious_characteristics'].append(name)
            
            return info
            
        except Exception as e:
            logger.warning(f"Error parsing PE file {file_path}: {e}")
            return {'is_pe': False, 'error': str(e)}
        finally:
            if 'pe' in locals():
                pe.close()
    
    @classmethod
    def extract_archive(cls, archive_path: Union[str, Path], 
                       extract_dir: Union[str, Path], 
                       password: Optional[str] = None) -> List[Path]:
        """Extract an archive file.
        
        Args:
            archive_path: Path to the archive file
            extract_dir: Directory to extract files to
            password: Optional password for encrypted archives
            
        Returns:
            List of extracted file paths
        """
        archive_path = Path(archive_path)
        extract_dir = Path(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        
        try:
            if archive_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    if password:
                        zip_ref.setpassword(password.encode())
                    zip_ref.extractall(extract_dir)
                    extracted_files = [extract_dir / f for f in zip_ref.namelist()]
                    
            elif archive_path.suffix.lower() in ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2'):
                mode = 'r:gz' if archive_path.suffix.lower().endswith('gz') else \
                       'r:bz2' if archive_path.suffix.lower().endswith('bz2') else 'r'
                with tarfile.open(archive_path, mode) as tar_ref:
                    tar_ref.extractall(extract_dir)
                    extracted_files = [extract_dir / f for f in tar_ref.getnames()]
                    
            elif archive_path.suffix.lower() == '.rar':
                with rarfile.RarFile(archive_path, 'r') as rar_ref:
                    if password:
                        rar_ref.setpassword(password)
                    rar_ref.extractall(extract_dir)
                    extracted_files = [extract_dir / f for f in rar_ref.namelist()]
                    
            elif archive_path.suffix.lower() == '.7z':
                with py7zr.SevenZipFile(archive_path, 'r', password=password) as sz_ref:
                    sz_ref.extractall(extract_dir)
                    extracted_files = [extract_dir / f for f in sz_ref.getnames()]
                    
            else:
                raise ValueError(f"Unsupported archive format: {archive_path.suffix}")
                
            return extracted_files
            
        except Exception as e:
            logger.error(f"Error extracting archive {archive_path}: {e}")
            raise
    
    @classmethod
    def is_archive(cls, file_path: Union[str, Path]) -> bool:
        """Check if a file is an archive.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file is an archive, False otherwise
        """
        file_path = Path(file_path)
        return file_path.suffix.lower() in {
            '.zip', '.tar', '.gz', '.tgz', '.bz2', '.tbz2', 
            '.rar', '.7z', '.xz', '.lzma', '.lz', '.lz4', '.zst'
        }
    
    @classmethod
    def is_pe_file(cls, file_path: Union[str, Path]) -> bool:
        """Check if a file is a PE (Portable Executable) file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file is a PE file, False otherwise
        """
        try:
            with open(file_path, 'rb') as f:
                # Check for 'MZ' signature
                if f.read(2) != b'MZ':
                    return False
                
                # Get PE header offset
                f.seek(60)
                pe_header_offset = int.from_bytes(f.read(4), byteorder='little')
                
                # Check for PE header
                f.seek(pe_header_offset)
                return f.read(4) == b'PE\x00\x00'
                
        except Exception:
            return False
    
    @classmethod
    def get_file_type(cls, file_path: Union[str, Path]) -> str:
        """Get the type of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            String describing the file type
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return "does not exist"
        
        if file_path.is_dir():
            return "directory"
            
        if not file_path.is_file():
            return "special file"
            
        # Check for PE files
        if cls.is_pe_file(file_path):
            try:
                pe = pefile.PE(str(file_path))
                if pe.is_dll():
                    return "PE DLL"
                elif pe.is_exe():
                    return "PE EXE"
                elif pe.is_driver():
                    return "PE Driver"
                else:
                    return "PE file"
            except Exception:
                return "corrupt PE file"
        
        # Check for archives
        if cls.is_archive(file_path):
            return f"{file_path.suffix[1:].upper()} archive"
        
        # Use file magic for other file types
        try:
            mime_type = cls._file_magic.from_file(str(file_path))
            return mime_type or "unknown"
        except Exception:
            return "unknown"

    @classmethod
    def safe_delete(cls, file_path: Union[str, Path], secure: bool = False) -> bool:
        """Safely delete a file with optional secure deletion.
        
        Args:
            file_path: Path to the file to delete
            secure: If True, overwrite the file with random data before deletion
            
        Returns:
            True if the file was deleted, False otherwise
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return True
            
        try:
            if secure:
                # Overwrite with random data before deletion
                file_size = file_path.stat().st_size
                with open(file_path, 'wb') as f:
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete the file
            file_path.unlink()
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
            return False
    
    @classmethod
    def is_safe_path(cls, base_path: Union[str, Path], path: Union[str, Path]) -> bool:
        """Check if a path is safe and within the base directory.
        
        Args:
            base_path: The base directory
            path: The path to check
            
        Returns:
            True if the path is safe, False otherwise
        """
        try:
            base_path = Path(base_path).resolve()
            path = Path(path).resolve()
            return base_path in path.parents or base_path == path
        except Exception:
            return False
