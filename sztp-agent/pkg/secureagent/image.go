/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureagent

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//nolint:funlen
func (a *Agent) downloadAndValidateImage() error {
	log.Printf("[INFO] Starting the Download Image: %v", a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI)
	_ = a.doReportProgress(ProgressTypeBootImageInitiated, "BootImage Initiated")
	// Download the image from DownloadURI and save it to a file
	a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference = fmt.Sprintf("%8d", time.Now().Unix())
	for i, item := range a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI {
		// TODO: maybe need to file download to a function in util.go
		log.Printf("[INFO] Downloading Image %v", item)
		// Create a empty file
		file, err := os.Create(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + filepath.Base(item))
		if err != nil {
			return err
		}
		err = a.downloadImage(item, file)
		if err != nil {
			return err
		}

		fileInfo, err := file.Stat()
		if err != nil {
			return err
		}
		size := fileInfo.Size()

		log.Printf("[INFO] Downloaded file: %s with size: %d", ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+filepath.Base(item), size)
		log.Println("[INFO] Verify the file checksum: ", ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+filepath.Base(item))
		switch a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.ImageVerification[i].HashAlgorithm {
		case "ietf-sztp-conveyed-info:sha-256":
			filePath := ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + filepath.Base(item)
			checksum, err := calculateSHA256File(filePath)
			original := strings.ReplaceAll(a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.ImageVerification[i].HashValue, ":", "")
			if err != nil {
				log.Println("[ERROR] Could not calculate checksum", err)
			}
			log.Println("calculated: " + checksum)
			log.Println("expected  : " + original)
			if checksum != original {
				return errors.New("checksum mismatch")
			}
			log.Println("[INFO] Checksum verified successfully")
			_ = a.doReportProgress(ProgressTypeBootImageComplete, "BootImage Complete")
			return nil
		default:
			return errors.New("unsupported hash algorithm")
		}
	}
	return nil
}
