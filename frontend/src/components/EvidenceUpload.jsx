import React, { useState } from 'react';
import { incidentAPI } from '../services/api';

const EvidenceUpload = ({ incidentId, onUpload }) => {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState('');

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setMessage('');
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage('Please select a file');
      return;
    }

    setUploading(true);
    setMessage('');

    try {
      await incidentAPI.uploadEvidence(incidentId, file);
      setMessage('✅ File uploaded successfully!');
      setFile(null);
      // Reset file input
      document.getElementById('file-input').value = '';
      if (onUpload) onUpload();
    } catch (error) {
      setMessage('❌ Upload failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center space-x-3">
        <input
          id="file-input"
          type="file"
          onChange={handleFileChange}
          className="block text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
        />
        <button
          onClick={handleUpload}
          disabled={!file || uploading}
          className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
        >
          {uploading ? 'Uploading...' : 'Upload'}
        </button>
      </div>
      {message && <p className="text-sm">{message}</p>}
    </div>
  );
};

export default EvidenceUpload;