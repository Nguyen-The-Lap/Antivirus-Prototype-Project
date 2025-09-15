import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useStore } from '../../store/useStore';
import { toast } from 'react-toastify';

// Type for scan result
interface ScanResult {
  infected: boolean;
  threats?: string[];
  scanTime?: string;
}

export const FileUploadCard = () => {
  const [isDragging, setIsDragging] = useState(false);
  const { scanFile, isScanning } = useStore();

  const onDrop = useCallback(
    async (acceptedFiles: File[]) => {
      if (acceptedFiles.length === 0) return;
      
      const file = acceptedFiles[0];
      try {
        const result: ScanResult = await scanFile(file);
        
        toast.success(
          result.infected 
            ? `Threat detected in ${file.name}`
            : `No threats found in ${file.name}`,
          {
            type: result.infected ? 'error' : 'success',
            autoClose: 5000,
          }
        );
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
        toast.error(`Error scanning file: ${errorMessage}`, {
          autoClose: 5000,
        });
      }
    },
    [scanFile]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    onDragEnter: () => setIsDragging(true),
    onDragLeave: () => setIsDragging(false),
    maxFiles: 1,
    accept: {
      'application/*': [
        '.exe', '.dll', '.msi', '.ps1', '.vbs', '.js', '.jar', '.bat', '.cmd',
        '.zip', '.rar', '.7z', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
      ],
      'image/*': ['.jpg', '.jpeg', '.png', '.gif'],
      'text/plain': ['.txt']
    },
  });

  return (
    <div 
      {...getRootProps()} 
      className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
        isDragActive || isDragging
          ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20'
          : 'border-gray-300 dark:border-gray-600 hover:border-indigo-400 dark:hover:border-indigo-500'
      }`}
    >
      <input {...getInputProps()} disabled={isScanning} />
      
      <div className="space-y-4">
        <div className="mx-auto h-16 w-16 text-indigo-500">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 8.25H7.5a2.25 2.25 0 00-2.25 2.25v9a2.25 2.25 0 002.25 2.25h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25H15m0-3l-3-3m0 0l-3 3m3-3V15"
            />
          </svg>
        </div>
        
        <div className="space-y-1">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            {isScanning 
              ? 'Scanning file...'
              : isDragActive 
                ? 'Drop the file here'
                : 'Drag and drop a file here'}
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {isScanning
              ? 'Please wait while we scan your file for threats...'
              : 'or click to browse files (Max 100MB)'}
          </p>
        </div>
        
        <div className="text-xs text-gray-500 dark:text-gray-400">
          <p>Supported formats: .exe, .dll, .msi, .zip, .pdf, .docx, .xlsx, .jpg, .png, etc.</p>
        </div>
        
        {!isScanning && (
          <button
            type="button"
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Select File
          </button>
        )}
      </div>
    </div>
  );
};
