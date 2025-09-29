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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// UnmarshalWithPrefetch deserializes ztoc data that may contain embedded prefetch files
// Expected blob structure: [ztoc] + [prefetch metadata] + [file1 content] + [file2 content] + ...
func UnmarshalWithPrefetch(data []byte) (*Ztoc, error) {
	// 首先尝试查找 JSON 元数据的开始位置
	// JSON 应该以 '{"layer_digest"' 开始
	jsonStart := bytes.Index(data, []byte(`{"layer_digest"`))
	if jsonStart == -1 {
		// 没有找到预取文件元数据，作为普通 ztoc 处理
		return flatbufToZtoc(data)
	}

	// 分离 ztoc 数据和预取文件数据
	ztocData := data[:jsonStart]
	prefetchData := data[jsonStart:]

	// 解析 ztoc
	ztoc, err := flatbufToZtoc(ztocData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ztoc: %w", err)
	}

	// 解析预取文件数据
	if err := parseAndLoadPrefetchData(ztoc, prefetchData); err != nil {
		return nil, fmt.Errorf("failed to parse prefetch data: %w", err)
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

// MarshalWithPrefetch serializes Ztoc with prefetch files and their content embedded in the same blob
// Blob structure: [ztoc] + [prefetch metadata] + [file1 content] + [file2 content] + ...
func MarshalWithPrefetch(ztoc *Ztoc, layerDigest string) (io.Reader, ocispec.Descriptor, error) {
	// 1. 正常序列化 ztoc
	ztocReader, ztocDesc, err := Marshal(ztoc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	// 2. 如果没有预取文件，直接返回原始数据
	if len(ztoc.PrefetchFiles) == 0 {
		return ztocReader, ztocDesc, nil
	}

	// 3. 读取 ztoc 数据
	ztocData, err := io.ReadAll(ztocReader)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	// 4. 计算预取文件内容的偏移量
	// 结构: [ztoc] + [metadata] + [file1] + [file2] + ...
	currentOffset := int64(len(ztocData))

	// 先计算元数据的大小（临时创建以获取大小）
	tempMetadata := PrefetchMetadata{
		LayerDigest:   layerDigest,
		PrefetchFiles: ztoc.PrefetchFiles, // 使用原始偏移量先计算
		CreatedAt:     time.Now(),
		Version:       "1.0",
	}
	tempMetadataBytes, err := json.Marshal(tempMetadata)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	// 元数据之后就是文件内容的开始位置
	currentOffset += int64(len(tempMetadataBytes))

	// 更新预取文件的偏移量为在索引 blob 中的位置
	updatedPrefetchFiles := make([]PrefetchFileInfo, len(ztoc.PrefetchFiles))
	for i, file := range ztoc.PrefetchFiles {
		updatedPrefetchFiles[i] = PrefetchFileInfo{
			Path:   file.Path,
			Size:   file.Size,
			Offset: currentOffset, // 在索引 blob 中的偏移量
		}
		// 移动到下一个文件的位置
		if i < len(ztoc.PrefetchFileContents) {
			currentOffset += int64(len(ztoc.PrefetchFileContents[i]))
		}
	}

	// 创建最终的元数据（包含更新后的偏移量）
	finalMetadata := PrefetchMetadata{
		LayerDigest:   layerDigest,
		PrefetchFiles: updatedPrefetchFiles,
		CreatedAt:     time.Now(),
		Version:       "1.0",
	}

	prefetchMetadata, err := json.Marshal(finalMetadata)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	// 5. 构建最终的 blob: ztoc + metadata + file contents
	totalSize := len(ztocData) + len(prefetchMetadata)
	for _, content := range ztoc.PrefetchFileContents {
		totalSize += len(content)
	}

	combinedData := make([]byte, 0, totalSize)

	// 添加 ztoc 数据
	combinedData = append(combinedData, ztocData...)

	// 添加预取文件元数据
	combinedData = append(combinedData, prefetchMetadata...)

	// 添加预取文件的实际内容
	for _, content := range ztoc.PrefetchFileContents {
		combinedData = append(combinedData, content...)
	}

	// 6. 创建新的 descriptor
	newDesc := ocispec.Descriptor{
		Digest: digest.FromBytes(combinedData),
		Size:   int64(len(combinedData)),
	}

	return bytes.NewReader(combinedData), newDesc, nil
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
