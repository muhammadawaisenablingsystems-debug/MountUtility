using System;
using System.IO;

namespace MountUtility.WPF.Helpers
{
    public static class FileIconHelper
    {
        public static string GetFileIcon(string fileName, bool isDirectory)
        {
            if (isDirectory)
            {
                return "\uE8B7";
            }

            var extension = Path.GetExtension(fileName).ToLowerInvariant();

            return extension switch
            {
                ".txt" => "\uE8A5",
                ".doc" or ".docx" => "\uE8A5",
                ".pdf" => "\uE8A5",
                ".xls" or ".xlsx" => "\uE8A5",
                ".ppt" or ".pptx" => "\uE8A5",
                ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".svg" => "\uE8B9",
                ".mp3" or ".wav" or ".flac" or ".aac" => "\uE8D6",
                ".mp4" or ".avi" or ".mkv" or ".mov" => "\uE8B2",
                ".zip" or ".rar" or ".7z" or ".tar" or ".gz" => "\uE8B5",
                ".exe" or ".msi" => "\uE8A7",
                ".cs" or ".cpp" or ".h" or ".java" or ".py" or ".js" or ".ts" or ".html" or ".css" or ".json" or ".xml" => "\uE8A5",
                _ => "\uE8A5"
            };
        }

        public static string GetFileTypeDescription(string fileName, bool isDirectory)
        {
            if (isDirectory)
            {
                return "File folder";
            }

            var extension = Path.GetExtension(fileName).ToLowerInvariant();

            return extension switch
            {
                ".txt" => "Text Document",
                ".doc" or ".docx" => "Word Document",
                ".pdf" => "PDF Document",
                ".xls" or ".xlsx" => "Excel Document",
                ".ppt" or ".pptx" => "PowerPoint Document",
                ".jpg" or ".jpeg" => "JPEG Image",
                ".png" => "PNG Image",
                ".gif" => "GIF Image",
                ".bmp" => "Bitmap Image",
                ".svg" => "SVG Image",
                ".mp3" => "MP3 Audio",
                ".wav" => "WAV Audio",
                ".flac" => "FLAC Audio",
                ".aac" => "AAC Audio",
                ".mp4" => "MP4 Video",
                ".avi" => "AVI Video",
                ".mkv" => "MKV Video",
                ".mov" => "QuickTime Video",
                ".zip" => "ZIP Archive",
                ".rar" => "RAR Archive",
                ".7z" => "7-Zip Archive",
                ".tar" => "TAR Archive",
                ".gz" => "GZ Archive",
                ".exe" => "Application",
                ".msi" => "Windows Installer",
                ".cs" => "C# Source File",
                ".cpp" => "C++ Source File",
                ".h" => "Header File",
                ".java" => "Java Source File",
                ".py" => "Python Script",
                ".js" => "JavaScript File",
                ".ts" => "TypeScript File",
                ".html" => "HTML Document",
                ".css" => "CSS File",
                ".json" => "JSON File",
                ".xml" => "XML File",
                _ => $"{extension.TrimStart('.').ToUpper()} File"
            };
        }
    }
}