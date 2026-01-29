package logreader

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hpowernl/hlogcli/internal/parser"
	"github.com/hpowernl/hlogcli/pkg/models"
)

// LogReader provides functionality to read log files
type LogReader struct {
	parser *parser.LogParser
}

// NewLogReader creates a new log reader
func NewLogReader() *LogReader {
	return &LogReader{
		parser: parser.NewLogParser(),
	}
}

// ReadFile reads a log file and returns a channel of log entries
func (r *LogReader) ReadFile(ctx context.Context, path string) (<-chan *models.LogEntry, <-chan error) {
	entryChan := make(chan *models.LogEntry, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(entryChan)
		defer close(errorChan)

		file, err := r.openFile(path)
		if err != nil {
			errorChan <- fmt.Errorf("failed to open file: %w", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		// Increase buffer size for large log lines
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				line := scanner.Text()
				if entry, err := r.parser.ParseLine(line); err == nil && entry != nil {
					entryChan <- entry
				}
			}
		}

		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading file: %w", err)
		}
	}()

	return entryChan, errorChan
}

// TailFile tails a log file and returns a channel of log entries
func (r *LogReader) TailFile(ctx context.Context, path string, follow bool) (<-chan *models.LogEntry, <-chan error) {
	entryChan := make(chan *models.LogEntry, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(entryChan)
		defer close(errorChan)

		// First, read existing content
		file, err := r.openFile(path)
		if err != nil {
			errorChan <- fmt.Errorf("failed to open file: %w", err)
			return
		}

		// Seek to end if following (if file supports seeking)
		if follow {
			if seeker, ok := file.(io.Seeker); ok {
				if _, err := seeker.Seek(0, io.SeekEnd); err != nil {
					file.Close()
					errorChan <- fmt.Errorf("failed to seek to end: %w", err)
					return
				}
			}
		}

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		if !follow {
			// Just read the file once
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					file.Close()
					return
				default:
					line := scanner.Text()
					if entry, err := r.parser.ParseLine(line); err == nil && entry != nil {
						entryChan <- entry
					}
				}
			}
			file.Close()
			return
		}

		// Follow mode - watch for changes
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			file.Close()
			errorChan <- fmt.Errorf("failed to create watcher: %w", err)
			return
		}
		defer watcher.Close()

		if err := watcher.Add(path); err != nil {
			file.Close()
			errorChan <- fmt.Errorf("failed to watch file: %w", err)
			return
		}

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				file.Close()
				return
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					// Read new lines
					for scanner.Scan() {
						line := scanner.Text()
						if entry, err := r.parser.ParseLine(line); err == nil && entry != nil {
							entryChan <- entry
						}
					}
				}
			case err := <-watcher.Errors:
				errorChan <- err
				file.Close()
				return
			case <-ticker.C:
				// Periodically check for new content
				for scanner.Scan() {
					line := scanner.Text()
					if entry, err := r.parser.ParseLine(line); err == nil && entry != nil {
						entryChan <- entry
					}
				}
			}
		}
	}()

	return entryChan, errorChan
}

// ReadStdin reads log entries from stdin
func (r *LogReader) ReadStdin(ctx context.Context) (<-chan *models.LogEntry, <-chan error) {
	entryChan := make(chan *models.LogEntry, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(entryChan)
		defer close(errorChan)

		scanner := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				line := scanner.Text()
				if entry, err := r.parser.ParseLine(line); err == nil && entry != nil {
					entryChan <- entry
				}
			}
		}

		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading stdin: %w", err)
		}
	}()

	return entryChan, errorChan
}

// WatchFile watches a file for changes and returns log entries
func (r *LogReader) WatchFile(ctx context.Context, path string) (<-chan *models.LogEntry, <-chan error) {
	return r.TailFile(ctx, path, true)
}

// ReadMultipleFiles reads multiple log files
func (r *LogReader) ReadMultipleFiles(ctx context.Context, paths []string) (<-chan *models.LogEntry, <-chan error) {
	entryChan := make(chan *models.LogEntry, 100)
	errorChan := make(chan error, len(paths))

	go func() {
		defer close(entryChan)
		defer close(errorChan)

		for _, path := range paths {
			select {
			case <-ctx.Done():
				return
			default:
				entries, errors := r.ReadFile(ctx, path)
				for entry := range entries {
					entryChan <- entry
				}
				for err := range errors {
					errorChan <- err
				}
			}
		}
	}()

	return entryChan, errorChan
}

// openFile opens a file, handling gzip compression
func (r *LogReader) openFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Check if file is gzipped
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return &gzipReadCloser{gzReader, file}, nil
	}

	return file, nil
}

// gzipReadCloser wraps a gzip.Reader and underlying file
type gzipReadCloser struct {
	gzReader *gzip.Reader
	file     *os.File
}

func (g *gzipReadCloser) Read(p []byte) (int, error) {
	return g.gzReader.Read(p)
}

func (g *gzipReadCloser) Close() error {
	g.gzReader.Close()
	return g.file.Close()
}

// DiscoverLogFiles discovers log files in common locations
func DiscoverLogFiles(baseDir string) ([]string, error) {
	var logFiles []string

	patterns := []string{
		"access.log*",
		"nginx/access.log*",
		"nginx/*/access.log*",
	}

	for _, pattern := range patterns {
		fullPattern := filepath.Join(baseDir, pattern)
		matches, err := filepath.Glob(fullPattern)
		if err != nil {
			continue
		}
		logFiles = append(logFiles, matches...)
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, file := range logFiles {
		if !seen[file] {
			seen[file] = true
			unique = append(unique, file)
		}
	}

	return unique, nil
}

// LogTailer provides advanced tailing functionality
type LogTailer struct {
	path   string
	follow bool
	reader *LogReader
}

// NewLogTailer creates a new log tailer
func NewLogTailer(path string, follow bool) *LogTailer {
	return &LogTailer{
		path:   path,
		follow: follow,
		reader: NewLogReader(),
	}
}

// Tail starts tailing the log file
func (t *LogTailer) Tail(ctx context.Context) (<-chan *models.LogEntry, <-chan error) {
	return t.reader.TailFile(ctx, t.path, t.follow)
}

// ReadLastN reads the last N lines from a file
func (r *LogReader) ReadLastN(path string, n int) ([]*models.LogEntry, error) {
	file, err := r.openFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read all lines
	var lines []string
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Take last N lines
	start := 0
	if len(lines) > n {
		start = len(lines) - n
	}

	entries := make([]*models.LogEntry, 0, n)
	for i := start; i < len(lines); i++ {
		if entry, err := r.parser.ParseLine(lines[i]); err == nil && entry != nil {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// FileInfo provides information about a log file
type FileInfo struct {
	Path       string
	Size       int64
	ModTime    time.Time
	IsGzipped  bool
	LineCount  int64
	FirstEntry time.Time
	LastEntry  time.Time
}

// GetFileInfo returns information about a log file
func (r *LogReader) GetFileInfo(path string) (*FileInfo, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	info := &FileInfo{
		Path:      path,
		Size:      stat.Size(),
		ModTime:   stat.ModTime(),
		IsGzipped: strings.HasSuffix(path, ".gz"),
	}

	// Count lines and get time range (sample first and last entries)
	file, err := r.openFile(path)
	if err != nil {
		return info, nil // Return partial info
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var firstEntry, lastEntry *models.LogEntry
	lineCount := int64(0)

	for scanner.Scan() {
		lineCount++
		if entry, err := r.parser.ParseLine(scanner.Text()); err == nil && entry != nil {
			if firstEntry == nil {
				firstEntry = entry
			}
			lastEntry = entry
		}
	}

	info.LineCount = lineCount
	if firstEntry != nil {
		info.FirstEntry = firstEntry.Timestamp
	}
	if lastEntry != nil {
		info.LastEntry = lastEntry.Timestamp
	}

	return info, nil
}
