package utils

import (
	"github.com/gofiber/fiber/v2/log"
)

func LogFatal(operation string, err error) {
	log.Fatalf("%s: %v", operation, err)
}

func LogError(operation string, err error) {
	log.Errorf("%s: %v", operation, err)
}

func LogWarn(operation string, message string) {
	log.Warnf("%s: %s", operation, message)
}

func LogInfo(operation string, message string) {
	log.Infof("%s: %s", operation, message)
}
