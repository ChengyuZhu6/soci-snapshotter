/*
   Copyright The Soci Snapshotter Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package ztoc

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/soci-snapshotter/ztoc/compression"
	ztoc_flatbuffers "github.com/awslabs/soci-snapshotter/ztoc/fbs/ztoc"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var ErrInvalidTOCEntry = errors.New("invalid toc entry")

// Marshal serializes Ztoc to its flatbuffers schema and returns a reader along with the descriptor (digest and size only).
// If not successful, it will return an error.
func Marshal(ztoc *Ztoc) (io.Reader, ocispec.Descriptor, error) {
	flatbuf, err := ztocToFlatbuffer(ztoc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	buf := bytes.NewReader(flatbuf)
	dgst := digest.FromBytes(flatbuf)
	size := len(flatbuf)
	return buf, ocispec.Descriptor{
		Digest: dgst,
		Size:   int64(size),
	}, nil
}

// Unmarshal takes the reader with flatbuffers byte stream and deserializes it ztoc.
// In case if there's any error situation during deserialization from flatbuffers, there will be an error returned.
func Unmarshal(serializedZtoc io.Reader) (*Ztoc, error) {
	flatbuf, err := io.ReadAll(serializedZtoc)
	if err != nil {
		return nil, err
	}

	return UnmarshalWithPrefetch(flatbuf)
}

// UnmarshalWithPrefetch deserializes ztoc data that may be in tar format containing ztoc.info + prefetch files
func UnmarshalWithPrefetch(data []byte) (*Ztoc, error) {
	// 尝试解析为 tar 格式
	tarReader := tar.NewReader(bytes.NewReader(data))

	var ztocData []byte
	var prefetchMetadata PrefetchMetadata
	prefetchFiles := make(map[string][]byte)

	// 遍历 tar 文件中的所有条目
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 如果不是 tar 格式，尝试作为原始 ztoc 数据处理
			return flatbufToZtoc(data)
		}

		switch header.Name {
		case "ztoc.info":
			// 读取 ztoc 数据
			ztocData, err = io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read ztoc.info: %w", err)
			}
		case "prefetch.json":
			// 读取预取文件元数据
			metadataBytes, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read prefetch.json: %w", err)
			}
			if err := json.Unmarshal(metadataBytes, &prefetchMetadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal prefetch metadata: %w", err)
			}
		default:
			// 读取预取文件内容
			fileContent, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read prefetch file %s: %w", header.Name, err)
			}
			prefetchFiles[header.Name] = fileContent
		}
	}

	// 如果没有找到 ztoc.info，尝试作为原始数据处理
	if len(ztocData) == 0 {
		return flatbufToZtoc(data)
	}

	// 解析 ztoc
	ztoc, err := flatbufToZtoc(ztocData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ztoc: %w", err)
	}

	// 如果有预取文件元数据，设置预取文件信息
	if len(prefetchMetadata.PrefetchFiles) > 0 {
		ztoc.PrefetchFiles = prefetchMetadata.PrefetchFiles

		// 验证预取文件内容是否存在
		for _, fileInfo := range ztoc.PrefetchFiles {
			if _, exists := prefetchFiles[fileInfo.Path]; !exists {
				fmt.Printf("Warning: prefetch file %s not found in tar archive\n", fileInfo.Path)
			}
		}
	}

	return ztoc, nil
}

// parseAndLoadPrefetchData 解析并加载预取文件数据
func parseAndLoadPrefetchData(ztoc *Ztoc, data []byte) error {
	// 查找 JSON 元数据的结束位置
	// JSON 数据应该以 '}' 结束，我们找到第一个完整的 JSON 对象

	var jsonEnd int = -1
	braceCount := 0
	inString := false
	escaped := false

	for i, b := range data {
		if escaped {
			escaped = false
			continue
		}

		if b == '\\' {
			escaped = true
			continue
		}

		if b == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		if b == '{' {
			braceCount++
		} else if b == '}' {
			braceCount--
			if braceCount == 0 {
				jsonEnd = i + 1
				break
			}
		}
	}

	if jsonEnd == -1 {
		return fmt.Errorf("could not find complete JSON metadata")
	}

	// 解析元数据
	metadataBytes := data[:jsonEnd]
	var metadata PrefetchMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal prefetch metadata: %w", err)
	}

	// 验证并更新文件内容偏移量
	fileContentStart := jsonEnd
	for i := range metadata.PrefetchFiles {
		// 更新偏移量为在当前 blob 中的位置
		metadata.PrefetchFiles[i].Offset = int64(fileContentStart)

		if fileContentStart+int(metadata.PrefetchFiles[i].Size) > len(data) {
			return fmt.Errorf("prefetch file %d extends beyond data boundary", i)
		}

		fileContentStart += int(metadata.PrefetchFiles[i].Size)
	}

	// 加载预取文件信息到 ztoc
	ztoc.PrefetchFiles = metadata.PrefetchFiles

	return nil
}

func flatbufToZtoc(flatbuffer []byte) (z *Ztoc, err error) {
	defer func() {
		if r := recover(); r != nil {
			z = nil
			err = fmt.Errorf("cannot unmarshal ztoc: %v", r)
		}
	}()

	// ztoc - metadata
	ztoc := new(Ztoc)
	ztocFlatbuf := ztoc_flatbuffers.GetRootAsZtoc(flatbuffer, 0)
	ztoc.Version = Version(ztocFlatbuf.Version())
	ztoc.BuildToolIdentifier = string(ztocFlatbuf.BuildToolIdentifier())
	ztoc.CompressedArchiveSize = compression.Offset(ztocFlatbuf.CompressedArchiveSize())
	ztoc.UncompressedArchiveSize = compression.Offset(ztocFlatbuf.UncompressedArchiveSize())

	// ztoc - toc
	fbtoc := new(ztoc_flatbuffers.TOC)
	ztocFlatbuf.Toc(fbtoc)

	toc, err := flatbufferToTOC(fbtoc)
	if err != nil {
		return nil, err
	}
	ztoc.TOC = toc

	// ztoc - zinfo
	compressionInfo := new(ztoc_flatbuffers.CompressionInfo)
	ztocFlatbuf.CompressionInfo(compressionInfo)
	ztoc.MaxSpanID = compression.SpanID(compressionInfo.MaxSpanId())
	ztoc.SpanDigests = make([]digest.Digest, compressionInfo.SpanDigestsLength())
	for i := 0; i < compressionInfo.SpanDigestsLength(); i++ {
		dgst, _ := digest.Parse(string(compressionInfo.SpanDigests(i)))
		ztoc.SpanDigests[i] = dgst
	}
	// Since compressionInfo.CheckpointsBytes() returns a slice,
	// we need to give it its own array so the GC can free compressionInfo.
	ztoc.Checkpoints = make([]byte, len(compressionInfo.CheckpointsBytes()))
	copy(ztoc.Checkpoints, compressionInfo.CheckpointsBytes())
	ztoc.CompressionAlgorithm = strings.ToLower(compressionInfo.CompressionAlgorithm().String())
	return ztoc, nil
}

func flatbufferToTOC(fbtoc *ztoc_flatbuffers.TOC) (TOC, error) {
	metadata := make([]FileMetadata, fbtoc.MetadataLength())
	toc := TOC{
		FileMetadata: metadata,
	}
	for i := 0; i < fbtoc.MetadataLength(); i++ {
		metadataEntry := new(ztoc_flatbuffers.FileMetadata)
		fbtoc.Metadata(metadataEntry, i)
		var me FileMetadata
		me.Name = string(metadataEntry.Name())
		me.Type = string(metadataEntry.Type())
		me.UncompressedOffset = compression.Offset(metadataEntry.UncompressedOffset())
		me.UncompressedSize = compression.Offset(metadataEntry.UncompressedSize())
		me.Linkname = string(metadataEntry.Linkname())
		me.Mode = metadataEntry.Mode()
		me.UID = int(metadataEntry.Uid())
		me.GID = int(metadataEntry.Gid())
		me.Uname = string(metadataEntry.Uname())
		me.Gname = string(metadataEntry.Gname())
		modTime := new(time.Time)
		modTime.UnmarshalText(metadataEntry.ModTime())
		me.ModTime = *modTime
		me.Devmajor = metadataEntry.Devmajor()
		me.Devminor = metadataEntry.Devminor()
		me.PAXHeaders = make(map[string]string)
		for j := 0; j < metadataEntry.XattrsLength(); j++ {
			xattrEntry := new(ztoc_flatbuffers.Xattr)
			metadataEntry.Xattrs(xattrEntry, j)
			key := string(xattrEntry.Key())
			value := string(xattrEntry.Value())
			me.PAXHeaders[key] = value
		}

		toc.FileMetadata[i] = me
	}

	sort.Slice(toc.FileMetadata, func(i, j int) bool {
		mi := &toc.FileMetadata[i]
		mj := &toc.FileMetadata[j]
		return mi.UncompressedOffset < mj.UncompressedOffset
	})

	// The first tar header is at offset 0
	nextTarHeader := compression.Offset(0)
	for i := range toc.FileMetadata {
		tocEntry := &toc.FileMetadata[i]
		if nextTarHeader > tocEntry.UncompressedOffset {
			return toc, ErrInvalidTOCEntry
		}
		tocEntry.TarHeaderOffset = nextTarHeader
		// The next tar header can be found immediately after the current file + padding
		nextTarHeader = AlignToTarBlock(tocEntry.UncompressedOffset + tocEntry.UncompressedSize)
	}
	return toc, nil
}

func ztocToFlatbuffer(ztoc *Ztoc) (fb []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			fb = nil
			err = fmt.Errorf("cannot marshal Ztoc to flatbuffers")
		}
	}()

	// ztoc - metadata
	builder := flatbuffers.NewBuilder(0)
	version := builder.CreateString(string(ztoc.Version))
	buildToolIdentifier := builder.CreateString(ztoc.BuildToolIdentifier)

	// ztoc - toc
	toc := tocToFlatbuffer(&ztoc.TOC, builder)

	// ztoc - zinfo
	checkpointsVector := builder.CreateByteVector(ztoc.Checkpoints)
	spanDigestsOffsets := make([]flatbuffers.UOffsetT, 0, len(ztoc.SpanDigests))
	for _, spanDigest := range ztoc.SpanDigests {
		off := builder.CreateString(spanDigest.String())
		spanDigestsOffsets = append(spanDigestsOffsets, off)
	}
	ztoc_flatbuffers.CompressionInfoStartSpanDigestsVector(builder, len(spanDigestsOffsets))
	for i := len(spanDigestsOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(spanDigestsOffsets[i])
	}
	spanDigests := builder.EndVector(len(spanDigestsOffsets))

	ztoc_flatbuffers.CompressionInfoStart(builder)
	ztoc_flatbuffers.CompressionInfoAddMaxSpanId(builder, int32(ztoc.MaxSpanID))
	ztoc_flatbuffers.CompressionInfoAddSpanDigests(builder, spanDigests)
	ztoc_flatbuffers.CompressionInfoAddCheckpoints(builder, checkpointsVector)

	// only add (and check) compression algorithm if not empty;
	// if empty, use Gzip as defined in ztoc flatbuf.
	if ztoc.CompressionAlgorithm != "" {
		compressionAlgorithm, err := compressionAlgorithmToFlatbuf(ztoc.CompressionAlgorithm)
		if err != nil {
			return nil, err
		}
		ztoc_flatbuffers.CompressionInfoAddCompressionAlgorithm(builder, compressionAlgorithm)
	}
	ztocInfo := ztoc_flatbuffers.CompressionInfoEnd(builder)

	ztoc_flatbuffers.ZtocStart(builder)
	ztoc_flatbuffers.ZtocAddVersion(builder, version)
	ztoc_flatbuffers.ZtocAddBuildToolIdentifier(builder, buildToolIdentifier)
	ztoc_flatbuffers.ZtocAddToc(builder, toc)
	ztoc_flatbuffers.ZtocAddCompressedArchiveSize(builder, int64(ztoc.CompressedArchiveSize))
	ztoc_flatbuffers.ZtocAddUncompressedArchiveSize(builder, int64(ztoc.UncompressedArchiveSize))
	ztoc_flatbuffers.ZtocAddCompressionInfo(builder, ztocInfo)
	ztocFlatbuf := ztoc_flatbuffers.ZtocEnd(builder)
	builder.Finish(ztocFlatbuf)
	return builder.FinishedBytes(), nil
}

// MarshalWithPrefetch creates a tar archive containing ztoc.info + prefetch.json + prefetch files
func MarshalWithPrefetch(ztoc *Ztoc, layerDigest string) (io.Reader, ocispec.Descriptor, error) {

	// 创建 tar 缓冲区
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)
	defer tarWriter.Close()

	// 1. 添加 ztoc.info 文件
	ztocReader, _, err := Marshal(ztoc)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to marshal ztoc: %w", err)
	}

	ztocData, err := io.ReadAll(ztocReader)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to read ztoc data: %w", err)
	}

	ztocHeader := &tar.Header{
		Name:    "ztoc.info",
		Mode:    0644,
		Size:    int64(len(ztocData)),
		ModTime: time.Now(),
	}
	if err := tarWriter.WriteHeader(ztocHeader); err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to write ztoc header: %w", err)
	}
	if _, err := tarWriter.Write(ztocData); err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to write ztoc data: %w", err)
	}

	// 2. 添加 prefetch.json 文件
	metadata := PrefetchMetadata{
		LayerDigest:   layerDigest,
		PrefetchFiles: ztoc.PrefetchFiles,
		CreatedAt:     time.Now(),
		Version:       "1.0",
	}

	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to marshal prefetch metadata: %w", err)
	}

	metadataHeader := &tar.Header{
		Name:    "prefetch.json",
		Mode:    0644,
		Size:    int64(len(metadataBytes)),
		ModTime: time.Now(),
	}
	if err := tarWriter.WriteHeader(metadataHeader); err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to write prefetch metadata header: %w", err)
	}
	if _, err := tarWriter.Write(metadataBytes); err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to write prefetch metadata: %w", err)
	}

	// 3. 添加实际的预取文件内容（保持原始路径）
	for i, fileInfo := range ztoc.PrefetchFiles {
		if i >= len(ztoc.PrefetchFileContents) {
			return nil, ocispec.Descriptor{}, fmt.Errorf("missing content for prefetch file %d", i)
		}

		fileContent := ztoc.PrefetchFileContents[i]
		fileHeader := &tar.Header{
			Name:    fileInfo.Path, // 使用原始文件路径
			Mode:    0644,
			Size:    int64(len(fileContent)),
			ModTime: time.Now(),
		}
		if err := tarWriter.WriteHeader(fileHeader); err != nil {
			return nil, ocispec.Descriptor{}, fmt.Errorf("failed to write prefetch file header for %s: %w", fileInfo.Path, err)
		}
		if _, err := tarWriter.Write(fileContent); err != nil {
			return nil, ocispec.Descriptor{}, fmt.Errorf("failed to write prefetch file content for %s: %w", fileInfo.Path, err)
		}
	}

	// 关闭 tar writer
	if err := tarWriter.Close(); err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to close tar writer: %w", err)
	}

	// 创建描述符
	tarData := tarBuf.Bytes()
	desc := ocispec.Descriptor{
		Digest: digest.FromBytes(tarData),
		Size:   int64(len(tarData)),
	}

	fmt.Printf("Created tar archive with ztoc.info + prefetch.json + %d prefetch files for layer %s\n",
		len(ztoc.PrefetchFiles), layerDigest)

	return bytes.NewReader(tarData), desc, nil
}

// SavePrefetchFiles saves prefetch files as separate files
func SavePrefetchFiles(ztoc *Ztoc, layerDigest string, baseDir string) error {
	if len(ztoc.PrefetchFiles) == 0 {
		return nil
	}

	// 创建预取文件目录
	prefetchDir := filepath.Join(baseDir, "prefetch", layerDigest)
	if err := os.MkdirAll(prefetchDir, 0755); err != nil {
		return fmt.Errorf("failed to create prefetch directory: %w", err)
	}

	// 保存预取文件元数据
	metadata := PrefetchMetadata{
		LayerDigest:   layerDigest,
		PrefetchFiles: ztoc.PrefetchFiles,
		CreatedAt:     time.Now(),
		Version:       "1.0",
	}

	metadataPath := filepath.Join(baseDir, "prefetch.json")
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal prefetch metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write prefetch metadata: %w", err)
	}

	// 保存每个预取文件的内容
	for i, fileInfo := range ztoc.PrefetchFiles {
		if i >= len(ztoc.PrefetchFileContents) {
			return fmt.Errorf("missing content for prefetch file %d", i)
		}

		// 使用文件路径的哈希作为文件名，避免路径冲突
		hasher := sha256.New()
		hasher.Write([]byte(fileInfo.Path))
		fileName := fmt.Sprintf("%x", hasher.Sum(nil))

		filePath := filepath.Join(prefetchDir, fileName)
		if err := os.WriteFile(filePath, ztoc.PrefetchFileContents[i], 0644); err != nil {
			return fmt.Errorf("failed to write prefetch file %s: %w", fileInfo.Path, err)
		}

		fmt.Printf("Saved prefetch file %s to %s\n", fileInfo.Path, filePath)
	}

	fmt.Printf("Saved %d prefetch files for layer %s\n", len(ztoc.PrefetchFiles), layerDigest)
	return nil
}

// LoadPrefetchFiles loads prefetch files from separate files
func LoadPrefetchFiles(layerDigest string, baseDir string) ([]PrefetchFileInfo, error) {
	metadataPath := filepath.Join(baseDir, "prefetch.json")

	// 检查元数据文件是否存在
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return nil, nil // 没有预取文件
	}

	// 读取元数据
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read prefetch metadata: %w", err)
	}

	var metadata PrefetchMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal prefetch metadata: %w", err)
	}

	// 只返回匹配的层的预取文件
	if metadata.LayerDigest != layerDigest {
		return nil, nil
	}

	return metadata.PrefetchFiles, nil
}

func tocToFlatbuffer(toc *TOC, builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	metadataOffsetList := make([]flatbuffers.UOffsetT, len(toc.FileMetadata))
	for i := len(toc.FileMetadata) - 1; i >= 0; i-- {
		me := toc.FileMetadata[i]
		// preparing the individual file medatada element
		metadataOffsetList[i] = prepareMetadataOffset(builder, me)
	}
	ztoc_flatbuffers.TOCStartMetadataVector(builder, len(toc.FileMetadata))
	for i := len(metadataOffsetList) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(metadataOffsetList[i])
	}
	metadata := builder.EndVector(len(toc.FileMetadata))

	ztoc_flatbuffers.TOCStart(builder)
	ztoc_flatbuffers.TOCAddMetadata(builder, metadata)
	return ztoc_flatbuffers.TOCEnd(builder)
}

func prepareMetadataOffset(builder *flatbuffers.Builder, me FileMetadata) flatbuffers.UOffsetT {
	name := builder.CreateString(me.Name)
	t := builder.CreateString(me.Type)
	linkName := builder.CreateString(me.Linkname)
	uname := builder.CreateString(me.Uname)
	gname := builder.CreateString(me.Gname)
	modTimeBinary, _ := me.ModTime.MarshalText()
	modTime := builder.CreateString(string(modTimeBinary))

	xattrs := prepareXattrsOffset(me, builder)

	ztoc_flatbuffers.FileMetadataStart(builder)
	ztoc_flatbuffers.FileMetadataAddName(builder, name)
	ztoc_flatbuffers.FileMetadataAddType(builder, t)
	ztoc_flatbuffers.FileMetadataAddUncompressedOffset(builder, int64(me.UncompressedOffset))
	ztoc_flatbuffers.FileMetadataAddUncompressedSize(builder, int64(me.UncompressedSize))
	ztoc_flatbuffers.FileMetadataAddLinkname(builder, linkName)
	ztoc_flatbuffers.FileMetadataAddMode(builder, me.Mode)
	ztoc_flatbuffers.FileMetadataAddUid(builder, uint32(me.UID))
	ztoc_flatbuffers.FileMetadataAddGid(builder, uint32(me.GID))
	ztoc_flatbuffers.FileMetadataAddUname(builder, uname)
	ztoc_flatbuffers.FileMetadataAddGname(builder, gname)
	ztoc_flatbuffers.FileMetadataAddModTime(builder, modTime)
	ztoc_flatbuffers.FileMetadataAddDevmajor(builder, me.Devmajor)
	ztoc_flatbuffers.FileMetadataAddDevminor(builder, me.Devminor)

	ztoc_flatbuffers.FileMetadataAddXattrs(builder, xattrs)

	off := ztoc_flatbuffers.FileMetadataEnd(builder)
	return off
}

func prepareXattrsOffset(me FileMetadata, builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	keys := make([]string, 0, len(me.PAXHeaders))
	for k := range me.PAXHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	xattrOffsetList := make([]flatbuffers.UOffsetT, 0, len(me.PAXHeaders))
	for _, key := range keys {
		keyOffset := builder.CreateString(key)
		valueOffset := builder.CreateString(me.PAXHeaders[key])
		ztoc_flatbuffers.XattrStart(builder)
		ztoc_flatbuffers.XattrAddKey(builder, keyOffset)
		ztoc_flatbuffers.XattrAddValue(builder, valueOffset)
		xattrOffset := ztoc_flatbuffers.XattrEnd(builder)
		xattrOffsetList = append(xattrOffsetList, xattrOffset)
	}
	ztoc_flatbuffers.FileMetadataStartXattrsVector(builder, len(xattrOffsetList))
	for j := len(xattrOffsetList) - 1; j >= 0; j-- {
		builder.PrependUOffsetT(xattrOffsetList[j])
	}
	xattrs := builder.EndVector(len(me.PAXHeaders))
	return xattrs
}

// compressionAlgorithmToFlatbuf helps convert compression algorithm into flatbuf
// enum. SOCI/containerd uses lower-case for compression, but our flatbuf capitalizes
// the first letter. When converting back, we can just `strings.ToLower` so a helper
// func is not needed in that case.
func compressionAlgorithmToFlatbuf(algo string) (ztoc_flatbuffers.CompressionAlgorithm, error) {
	for k, v := range ztoc_flatbuffers.EnumValuesCompressionAlgorithm {
		if strings.ToLower(k) == algo {
			return v, nil
		}
	}
	return 0, fmt.Errorf("compression algorithm not defined in flatbuf: %s", algo)
}
