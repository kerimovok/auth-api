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

func LogWarn(message string) {
	log.Warnf("%s", message)
}

func LogInfo(message string) {
	log.Infof("%s", message)
}
