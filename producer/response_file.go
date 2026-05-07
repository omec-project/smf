package producer

import "os"

func createResponseBinaryFile(payload []byte) (*os.File, error) {
	tmpFile, err := os.CreateTemp("", "prefix")
	if err != nil {
		return nil, err
	}
	fileName := tmpFile.Name()
	if _, err = tmpFile.Write(payload); err != nil {
		tmpFile.Close()
		return nil, err
	}
	if err = tmpFile.Close(); err != nil {
		return nil, err
	}
	return os.Open(fileName)
}
