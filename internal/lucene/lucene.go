// This package provides Go implementations of code from Apache Lucene
// https://github.com/apache/lucene

package lucene

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// this function is implemented by child classes of DataInput, but i am lazy
func ReadByte(in *os.File) (byte, error) {
	byteArr := make([]byte, 1)

	n, err := in.Read(byteArr)
	if err != nil {
		return 0, err
	}

	if n != 1 {
		return 0, errors.New("didn't read enough bytes from file")
	}

	return byteArr[0], nil
}

// FROM HERE DOWN IS FROM CodecUtil.java, commit b84e0c272b

var CODEC_MAGIC int32 = 0x3fd76c17
var FOOTER_MAGIC int32 = ^CODEC_MAGIC

func CheckHeader(in *os.File, codec string, minVersion int32, maxVersion int32) (int32, error) {
	codecHeaderInt, err := ReadBEInt(in)
	if err != nil {
		return 0, err
	}

	if codecHeaderInt != CODEC_MAGIC {
		return 0, errors.New("invalid magic bytes in codec header, is this a valid Elasticsearch keystore?")
	}

	return CheckHeaderNoMagic(in, codec, minVersion, maxVersion)
}

func CheckHeaderNoMagic(in *os.File, codec string, minVersion int32, maxVersion int32) (int32, error) {
	actualCodec, err := ReadString(in)
	if err != nil {
		return 0, err
	}

	if actualCodec != codec {
		return 0, errors.New("corrupted index, bad codec found")
	}

	actualVersion, err := ReadBEInt(in)
	if err != nil {
		return 0, err
	}

	if actualVersion < minVersion {
		return 0, errors.New("version of the index is too old")
	}

	if actualVersion > maxVersion {
		return 0, errors.New("version of the index is too new")
	}

	return actualVersion, nil
}

// returns nil if all good
func CheckFooter(in *os.File) error {
	// a CRC32 is calculated and updated as bytes are read from the file
	// however, i am lazy
	// TODO check CRC32

	// real code does file length checks and such, but again, i am lazy
	// just make sure the footer is there, and error out if not

	footer, err := ReadBEInt(in)
	if err != nil {
		return err
	}

	if footer != FOOTER_MAGIC {
		return fmt.Errorf("got a bad footer magic value: %#x (expcted %#x)", footer, uint64(FOOTER_MAGIC))
	}

	algo, err := ReadBEInt(in)
	if err != nil {
		return err
	}

	if algo != 0 {
		return fmt.Errorf("got a bad algo value: %#x", algo)
	}

	// this is where crc32 code would go
	// there should only be 8 bytes left in the file

	return nil
}

// read a big endian 32bit int from the provided file
func ReadBEInt(in *os.File) (int32, error) {
	byteArr := make([]byte, 4)

	n, err := in.Read(byteArr)
	if err != nil {
		return 0, err
	}

	if n != 4 {
		return 0, errors.New("didn't read enough bytes from file")
	}

	intVal := binary.BigEndian.Uint32(byteArr)

	return int32(intVal), nil
}

// FROM HERE DOWN IS FROM DataInput.java, commit b84e0c272b

// read a string from the file
func ReadString(in *os.File) (string, error) {
	length, err := ReadVInt(in)
	if err != nil {
		return "", err
	}

	byteArr := make([]byte, length)
	n, err := in.Read(byteArr)
	if err != nil {
		return "", err
	}

	if n != length {
		return "", errors.New("didn't read enough bytes from file")
	}

	return string(byteArr), nil
}

// read in a variable length int, between one and five bytes
func ReadVInt(in *os.File) (int, error) {
	b, err := ReadByte(in)
	if err != nil {
		return 0, err
	}

	i := int(b) & 0x7f

	for shift := 7; b&0x80 != 0; shift += 7 {
		b, err := ReadByte(in)
		if err != nil {
			return 0, err
		}

		i |= (int(b) & 0x7f) << shift
	}

	return i, nil
}

func ReadMapOfStrings(in *os.File) (map[string]string, error) {
	count, err := ReadVInt(in)
	if err != nil {
		return nil, err
	}

	if count == 0 {
		return map[string]string{}, nil
	} else {
		m := make(map[string]string)

		for i := 0; i < count; i++ {
			key, err := ReadString(in)
			if err != nil {
				return nil, err
			}

			val, err := ReadString(in)
			if err != nil {
				return nil, err
			}

			m[key] = val
		}

		return m, nil
	}
}
